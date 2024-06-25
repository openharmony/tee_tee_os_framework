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

#include "soft_ec_api.h"
#include <ec/ec_local.h>
#include <crypto/evp.h>
#include <crypto/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <securec.h>
#include <tee_log.h>
#include "crypto_inner_interface.h"
#include "soft_gmssl.h"
#include "soft_common_api.h"
#include "soft_err.h"

#define KEY_SIZE_25519               256
#define ED25519_PUBLIC_KEY_LEN       32
#define ED25519_PRI_KEY_LEN          32
#define X25519_PUBLIC_KEY_LEN        32
#define X25519_PRIVATE_KEY_LEN       32
#define ECC224_DX_SIGN_FIX_LEN       56
#define ECC256_DX_SIGN_FIX_LEN       64
#define ECC384_DX_SIGN_FIX_LEN       96
#define ECC521_DX_SIGN_FIX_LEN       132


static EVP_PKEY *generate_evp_key(int32_t id)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(id, NULL);
    if (pctx == NULL) {
        tloge("New evp ctx failed, id=%d\n", id);
        return NULL;
    }
    int rc = EVP_PKEY_keygen_init(pctx);
    if (rc <= 0) {
        tloge("Evp init failed, id=%d\n", id);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    rc = EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    if (rc <= 0) {
        tloge("Generate evp failed, id=%d\n", id);
        return NULL;
    }

    return pkey;
}

static int32_t generate_ed25519_keypair(uint32_t key_size, struct ecc_pub_key_t *public_key,
    struct ecc_priv_key_t *private_key)
{
    if (key_size != KEY_SIZE_25519) {
        tloge("key size is Invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    EVP_PKEY *pkey = generate_evp_key(EVP_PKEY_ED25519);
    if (pkey == NULL) {
        tloge("Evp generate failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    size_t pub_key_buf_len = ECC_KEY_LEN;
    size_t prv_key_buf_len = ECC_KEY_LEN;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, private_key->r, sizeof(private_key->r), &prv_key_buf_len) == 0)
    {
        tloge("Get private key failed\n");
        EVP_PKEY_free(pkey);
        return CRYPTO_ERROR_SECURITY;
    }

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, public_key->x, sizeof(public_key->x), &pub_key_buf_len) == 0)
    {
        tloge("Get public key failed\n");
        EVP_PKEY_free(pkey);
        return CRYPTO_ERROR_SECURITY;
    }

    EVP_PKEY_free(pkey);

    public_key->x_len = ED25519_PUBLIC_KEY_LEN;
    private_key->r_len = ED25519_PRI_KEY_LEN;
    return CRYPTO_SUCCESS;
}

static int32_t generate_x25519_keypair(uint32_t key_size, struct ecc_pub_key_t *public_key,
    struct ecc_priv_key_t *private_key)
{
    if (key_size != KEY_SIZE_25519) {
        tloge("key size is Invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    EVP_PKEY *pkey = generate_evp_key(EVP_PKEY_X25519);
    if (pkey == NULL) {
        tloge("Evp generate failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    ECX_KEY *x25519_key = EVP_PKEY_get0(pkey);
    bool check_null = (x25519_key == NULL) || (x25519_key->privkey == NULL);
    if (check_null) {
        tloge("Evp get failed\n");
        EVP_PKEY_free(pkey);
        return CRYPTO_BAD_PARAMETERS;
    }
    errno_t rc = memcpy_s(public_key->x, public_key->x_len, x25519_key->pubkey, X25519_PUBLIC_KEY_LEN);
    if (rc != EOK) {
        tloge("Copy failed, rc=%d\n", rc);
        EVP_PKEY_free(pkey);
        return CRYPTO_ERROR_SECURITY;
    }
    rc = memcpy_s(private_key->r, private_key->r_len, x25519_key->privkey, X25519_PRIVATE_KEY_LEN);
    EVP_PKEY_free(pkey);
    if (rc != EOK) {
        tloge("Copy failed, rc=%d\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    public_key->x_len = X25519_PUBLIC_KEY_LEN;
    private_key->r_len = X25519_PRIVATE_KEY_LEN;

    return CRYPTO_SUCCESS;
}

static int32_t soft_fill_zero_to_head(uint32_t keysize, uint8_t *x, uint32_t *x_len)
{
    errno_t rc;
    uint32_t need_buffer_size = (keysize + BIT_NUMBER_SEVEN) >> BIT_TO_BYTE_MOVE_THREE;
    if (*x_len < need_buffer_size) {
        rc = memmove_s(x + (need_buffer_size - *x_len), EC_KEY_FIX_BUFFER_LEN - (need_buffer_size - *x_len),
            x, *x_len);
        if (rc != EOK) {
            tloge("memove error in fill zero");
            return CRYPTO_ERROR_SECURITY;
        }

        rc = memset_s(x, need_buffer_size - *x_len, 0, need_buffer_size - *x_len);
        if (rc != EOK) {
            tloge("memset error in fill zero");
            return CRYPTO_ERROR_SECURITY;
        }
        *x_len = need_buffer_size;
    }
    return CRYPTO_SUCCESS;
}

static int32_t config_crypto_engine_biringssl_judg(uint32_t key_size, struct ecc_pub_key_t *public_key,
                                                   const BIGNUM *x, const BIGNUM *y)
{
    int32_t x_len = BN_bn2bin(x, public_key->x);
    int32_t y_len = BN_bn2bin(y, public_key->y);

    bool check = (x_len <= 0 ||  y_len <= 0);
    if (check) {
        tloge("x_len or y_len is no more than 0");
        return CRYPTO_BAD_PARAMETERS;
    }
    public_key->x_len = (uint32_t)x_len;
    public_key->y_len = (uint32_t)y_len;
    int32_t ret = soft_fill_zero_to_head(key_size, public_key->x, &(public_key->x_len));
    if (ret != CRYPTO_SUCCESS) {
        tloge("ret is not CRYPTO_SUCCESS");
        return ret;
    }

    ret = soft_fill_zero_to_head(key_size, public_key->y, &(public_key->y_len));
    if (ret != CRYPTO_SUCCESS)
        tloge("ret is not CRYPTO_SUCCESS");
    return ret;
}

static int32_t soft_ecpubkey_boring_to_tee(const EC_KEY *key, uint32_t key_size, struct ecc_pub_key_t *public_key)
{
    int32_t ret = CRYPTO_BAD_PARAMETERS;
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    bool check = (x == NULL || y == NULL);
    if (check) {
        tloge("new bn error in boring pub to tee pub");
        goto error;
    }

    const EC_POINT *point = EC_KEY_get0_public_key(key);
    if (point == NULL) {
        tloge("boring ec key get public key error");
        goto error;
    }
    ret = EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key), point, x, y, NULL);
    if (ret == BORINGSSL_ERR) {
        tloge("boring ec key get public x y error");
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto error;
    }
    check = (BN_num_bytes(x) > ECC_KEY_LEN || BN_num_bytes(y) > ECC_KEY_LEN);
    if (check) {
        tloge("buffer not enough");
        ret = CRYPTO_BAD_PARAMETERS;
        goto error;
    }
    ret = config_crypto_engine_biringssl_judg(key_size, public_key, x, y);
error:
    BN_free(x);
    BN_free(y);
    return ret;
}

static int32_t soft_eckey_boring_to_tee(const EC_KEY *key, uint32_t key_size, struct ecc_pub_key_t *public_key,
    struct ecc_priv_key_t *private_key)
{
    const BIGNUM *priv_bn = EC_KEY_get0_private_key(key);
    if (priv_bn == NULL) {
        tloge("ec key error, get private fail");
        return CRYPTO_BAD_PARAMETERS;
    }
    size_t private_len = (size_t)BN_num_bytes(priv_bn);
    if (private_len > ECC_KEY_LEN) {
        tloge("private key to buffer error, len %zu", private_len);
        priv_bn = NULL;
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t priv_key_len = BN_bn2bin(priv_bn, private_key->r);
    if (priv_key_len <= 0)
        return CRYPTO_BAD_PARAMETERS;

    private_key->r_len = (uint32_t)priv_key_len;
    if (key_size == ECDSA_KEY_521)
        key_size = EC_KEY_FIX_BUFFER_LEN * BIT_TO_BYTE;

    int32_t ret = soft_fill_zero_to_head(key_size, private_key->r, &(private_key->r_len));
    if (ret != TEE_SUCCESS)
        return ret;

    /* change boringssl public key to buffer */
    ret = soft_ecpubkey_boring_to_tee(key, key_size, public_key);
    if (ret != TEE_SUCCESS) {
        priv_bn = NULL;
        tloge("boring public key to tee public error");
    }

    return ret;
}

static int32_t get_ec_sign_size_by_domain(uint32_t domain)
{
    uint32_t index                       = 0;
    crypto_uint2uint domain_to_sig_len[] = {
        { ECC_CURVE_NIST_P224, ECC224_DX_SIGN_FIX_LEN },
        { ECC_CURVE_NIST_P256, ECC256_DX_SIGN_FIX_LEN },
        { ECC_CURVE_NIST_P384, ECC384_DX_SIGN_FIX_LEN },
        { ECC_CURVE_NIST_P521, ECC521_DX_SIGN_FIX_LEN },
    };
    for (; index < sizeof(domain_to_sig_len) / sizeof(crypto_uint2uint); index++) {
        if (domain == domain_to_sig_len[index].src)
            return domain_to_sig_len[index].dest;
    }
    tloge("invalid tee_domain 0x%x\n", domain);
    return 0;
}

static int32_t soft_ecc_sign_to_bin(const ECDSA_SIG *sig_data, void *signature, uint32_t signature_len)
{
    errno_t rc;
    BIGNUM *out_r = NULL;
    BIGNUM *out_s = NULL;
    int32_t move_len;
    int32_t fix_r_s_len = (int32_t)(signature_len / SOFT_NUMBER_TWO);
    int32_t r_len;
    int32_t s_len;

    rc = memset_s(signature, signature_len, 0, signature_len);
    if (rc != EOK) {
        tloge("mem signature fail");
        return CRYPTO_ERROR_SECURITY;
    }
    ECDSA_SIG_get0(sig_data, (const BIGNUM **)&out_r, (const BIGNUM **)&out_s);
    if (out_r == NULL || out_s == NULL) {
        tloge("bad ecc sign result");
        return CRYPTO_BAD_PARAMETERS;
    }
    r_len = BN_num_bytes(out_r);
    s_len = BN_num_bytes(out_s);
    if (r_len > fix_r_s_len || s_len > fix_r_s_len) {
        tloge("bad ecc sign result,it too large %d, %d", r_len, s_len);
        return CRYPTO_BAD_PARAMETERS;
    }

    move_len = fix_r_s_len - r_len;
    r_len = BN_bn2bin(out_r, signature + move_len);

    move_len = (int32_t)signature_len - s_len;
    s_len = BN_bn2bin(out_s, signature + move_len);
    if (r_len <= 0 || s_len <= 0 || r_len > fix_r_s_len || s_len > fix_r_s_len) {
        tloge("when fill res, bad ecc sign result,the len is %d, %d", r_len, s_len);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t ecdsa_sign_digest(const struct ecc_priv_key_t *priv,
    const struct memref_t *digest, struct memref_t *signature)
{
    EC_KEY *eckey = NULL;
    struct ecc_priv_key_t *private = (struct ecc_priv_key_t *)priv;
    uint32_t tee_domain = priv->domain_id;
    int32_t ret = get_boring_nid_by_tee_curve(priv->domain_id, &private->domain_id);
    if (ret != CRYPTO_SUCCESS) {
        tloge("change nid fail");
        return ret;
    }
    ret = (int32_t)ecc_privkey_tee_to_boring(private, (void **)&eckey);
    private->domain_id = tee_domain;
    if (ret != CRYPTO_SUCCESS) {
        tloge("Tee Private Key To Boring Key error");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    uint8_t *signature_buffer = (uint8_t *)(uintptr_t)(signature->buffer);

    ECDSA_SIG *sig_data = ECDSA_do_sign((const unsigned char *)(uintptr_t)digest->buffer, digest->size, eckey);
    EC_KEY_free(eckey);
    eckey = NULL;
    if (sig_data == NULL) {
        tloge("boring sign error");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    uint32_t sig_size = (uint32_t)get_ec_sign_size_by_domain(tee_domain);
    if (sig_size == 0) {
        ECDSA_SIG_free(sig_data);
        tloge("bad domain %u", tee_domain);
        return CRYPTO_BAD_PARAMETERS;
    }
    ret = soft_ecc_sign_to_bin(sig_data, signature_buffer, sig_size);
    ECDSA_SIG_free(sig_data);
    signature->size = sig_size;
    return ret;
}

#define COMPUTE_BYTE_LEN (BIT_TO_BYTE - 1)
static int32_t soft_ecc_sign_to_boringssl(ECDSA_SIG *sig, const void *signature, uint32_t signature_len)
{
    bool check = (sig == NULL || signature_len == 0);
    if (check) {
        tloge("sig is null");
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t r_s_len = (int32_t)(signature_len / SOFT_NUMBER_TWO);
    BIGNUM *r = BN_bin2bn(signature, r_s_len, NULL);
    BIGNUM *s = BN_bin2bn(signature + r_s_len, r_s_len, NULL);
    check = (r == NULL || s == NULL);
    if (check) {
        BN_free(r);
        BN_free(s);
        tloge("bn to bn fail");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (ECDSA_SIG_set0(sig, r, s) == 0) {
        BN_free(r);
        BN_free(s);
        tloge("set r s to ecdsa sig fail");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

static int32_t soft_boring_ecc_verify(const struct ecc_pub_key_t *pub, const void *digest, uint32_t digest_len,
    const ECDSA_SIG *sig)
{
    EC_KEY *eckey = NULL;
    struct ecc_pub_key_t *public = (struct ecc_pub_key_t *)pub;
    uint32_t tee_domain = pub->domain_id;

    int32_t ret = get_boring_nid_by_tee_curve(pub->domain_id, &public->domain_id);
    if (ret != CRYPTO_SUCCESS) {
        tloge("change nid fail");
        return ret;
    }

    ret = (int32_t)ecc_pubkey_tee_to_boring(public, &eckey);
    public->domain_id = tee_domain;
    if (ret != CRYPTO_SUCCESS) {
        tloge("PubKeyToBoringKey key error");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    ret = ECDSA_do_verify(digest, (int32_t)digest_len, sig, eckey);
    EC_KEY_free(eckey);
    eckey = NULL;
    if (ret != BORINGSSL_OK) {
        tloge("boring verify error");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    return CRYPTO_SUCCESS;
}

static int32_t ecdsa_verify_digest(const struct ecc_pub_key_t *public_key,
    const struct memref_t *digest, const struct memref_t *signature)
{
    bool is_dx_sig = (signature->size == ECC224_DX_SIGN_FIX_LEN || signature->size == ECC256_DX_SIGN_FIX_LEN ||
        signature->size == ECC384_DX_SIGN_FIX_LEN || signature->size == ECC521_DX_SIGN_FIX_LEN);
    if (!is_dx_sig) {
        tloge("not good sign len, sign len is 0x%x", signature->size);
        return CRYPTO_BAD_PARAMETERS;
    }
    ECDSA_SIG *sig = ECDSA_SIG_new();
    uint8_t *digest_buffer = (uint8_t *)(uintptr_t)(digest->buffer);
    uint8_t *signature_buffer = (uint8_t *)(uintptr_t)(signature->buffer);

    int32_t ret = soft_ecc_sign_to_boringssl(sig, signature_buffer, signature->size);
    if (ret != CRYPTO_SUCCESS) {
        ECDSA_SIG_free(sig);
        tloge("ecc key convert fail");
        return ret;
    }

    ret = soft_boring_ecc_verify(public_key, digest_buffer, digest->size, sig);
    ECDSA_SIG_free(sig);
    if (ret != CRYPTO_SUCCESS)
        tloge("ecc verify fail");
    return ret;
}

typedef int32_t (*copy_ctx_func)(struct ctx_handle_t *dest, const struct ctx_handle_t *src);
struct soft_ctx_copy {
    uint32_t algorithm;
    copy_ctx_func copy_call_back;
};

static int32_t generate_ecc_keypair(uint32_t curve, uint32_t key_size,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    uint32_t nid;
    int32_t ret = get_boring_nid_by_tee_curve(curve, &nid);
    if (ret != CRYPTO_SUCCESS) {
        tloge("get boring nid error");
        return ret;
    }

    EC_KEY *key = EC_KEY_new_by_curve_name(nid);
    if (key == NULL) {
        tloge("key is null, nid not support %u", nid);
        return CRYPTO_BAD_PARAMETERS;
    }
    if (EC_KEY_generate_key(key) == 0) {
        tloge("boring ssl generate key fail");
        EC_KEY_free(key);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    ret = soft_eckey_boring_to_tee(key, key_size, public_key, private_key);
    EC_KEY_free(key);
    return ret;
}

int32_t soft_crypto_ecc_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    bool check = (public_key == NULL || private_key == NULL);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (curve == ECC_CURVE_ED25519)
        return generate_ed25519_keypair(key_size, public_key, private_key);

    if (curve == ECC_CURVE_X25519)
        return generate_x25519_keypair(key_size, public_key, private_key);

    check = (curve == ECC_CURVE_NIST_P192 || curve == ECC_CURVE_NIST_P224 ||
        curve == ECC_CURVE_NIST_P256 || curve == ECC_CURVE_NIST_P384 || curve == ECC_CURVE_NIST_P521);
    if (check)
        return generate_ecc_keypair(curve, key_size, public_key, private_key);

    return CRYPTO_NOT_SUPPORTED;
}

int32_t soft_crypto_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)ec_params;
    bool check = (public_key == NULL || data_in == NULL || data_out == NULL || data_in->buffer == 0 ||
        data_out->buffer == 0);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (alg_type == CRYPTO_TYPE_SM2_PKE)
        return CRYPTO_NOT_SUPPORTED;

    return CRYPTO_NOT_SUPPORTED;
}

int32_t soft_crypto_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)ec_params;
    bool check = (private_key == NULL || data_in == NULL || data_out == NULL || data_in->buffer == 0 ||
        data_out->buffer == 0);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (alg_type == CRYPTO_TYPE_SM2_PKE)
        return CRYPTO_NOT_SUPPORTED;

    return CRYPTO_NOT_SUPPORTED;
}

static int32_t ed25519_sign_digest(struct memref_t *signature, const struct memref_t *digest,
    const struct ecc_priv_key_t *private_key)
{
#ifdef CRYPTO_SSL_SUPPORT_EC25519
    if (signature->size < ED25519_SIGN_LEN) {
        tloge("sign out len too small 0x%x", signature->size);
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t sign_ret;
    uint8_t *digest_buffer = (uint8_t *)(uintptr_t)(digest->buffer);
    uint8_t *signature_buffer = (uint8_t *)(uintptr_t)(signature->buffer);

#ifdef OPENSSL3_ENABLE
    sign_ret = ossl_ed25519_sign(signature_buffer, digest_buffer, digest->size,
        private_key->r + X25519_SHARE_KEY_LEN, private_key->r, NULL, NULL);
#else
    sign_ret = ED25519_sign(signature_buffer, digest_buffer, digest->size,
        private_key->r + X25519_SHARE_KEY_LEN, private_key->r);
#endif
    if (sign_ret != BORINGSSL_OK) {
        tloge("ed25519 sign fail");
        return CRYPTO_BAD_PARAMETERS;
    }
    signature->size = ED25519_SIGN_LEN;
    return CRYPTO_SUCCESS;
#else
    (void)signature;
    (void)digest;
    (void)private_key;
    return CRYPTO_NOT_SUPPORTED;
#endif
}

int32_t soft_crypto_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    struct memref_t *signature)
{
    (void)ec_params;
    bool check = (private_key == NULL || digest == NULL || signature == NULL || digest->buffer == 0 ||
        signature->buffer == 0);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (alg_type == CRYPTO_TYPE_ED25519)
        return ed25519_sign_digest(signature, digest, private_key);

    return ecdsa_sign_digest(private_key, digest, signature);
}

static int32_t ed25519_verify_digest(const struct memref_t *signature, const struct memref_t *digest,
    const struct ecc_pub_key_t *public_key)
{
#ifdef CRYPTO_SSL_SUPPORT_EC25519
    if (signature->size != ED25519_SIGN_LEN) {
        tloge("sign len error 0x%x", signature->size);
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *signature_buffer = (uint8_t *)(uintptr_t)(signature->buffer);

#ifdef OPENSSL3_ENABLE
    int32_t verf_ret = ossl_ed25519_verify((const uint8_t *)(uintptr_t)digest->buffer,
        digest->size, signature_buffer, public_key->x, NULL, NULL);
#else
    int32_t verf_ret = ED25519_verify((const uint8_t *)(uintptr_t)digest->buffer,
        digest->size, signature_buffer, public_key->x);
#endif
    if (verf_ret != BORINGSSL_OK) {
        tloge("soft verify fail");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
#else
    (void)signature;
    (void)digest;
    (void)public_key;
    return CRYPTO_NOT_SUPPORTED;
#endif
}

int32_t soft_crypto_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    const struct memref_t *signature)
{
    (void)ec_params;
    bool check = (public_key == NULL || digest == NULL || signature == NULL || digest->buffer == 0 ||
        signature->buffer == 0);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (alg_type == CRYPTO_TYPE_ED25519)
        return ed25519_verify_digest(signature, digest, public_key);

    return ecdsa_verify_digest(public_key, digest, signature);
}
