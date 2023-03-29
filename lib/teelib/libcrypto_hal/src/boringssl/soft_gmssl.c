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

#include "soft_gmssl.h"
#include "gmssl_internal.h"
#include "soft_err.h"
#include <securec.h>
#include <openssl/hmac.h>
#include <crypto/sm2.h>
#include <evp/evp_local.h>
#include <hmac/hmac_local.h>
#include <openssl/ossl_typ.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <tee_log.h>
#include <tee_crypto_api.h>
#include <tee_property_inner.h>
#include "crypto_inner_defines.h"
#include <openssl/ossl_typ.h>

#define LOW_FOUR_BITS       4
#define LOW_FOUR_BITS_MASK  0xf
#define DEST_DATA_TEMP      16

struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

void SM2_Ciphertext_free(struct SM2_Ciphertext_st *);
int i2d_SM2_Ciphertext(struct SM2_Ciphertext_st *a, unsigned char **out);
struct SM2_Ciphertext_st *d2i_SM2_Ciphertext(struct SM2_Ciphertext_st **a, const unsigned char **in, long len);

static void gmssl_generate_random(void)
{
    char rand_seed[RAND_SIZE] = { 0 };
    uint32_t rand_seed_size   = RAND_SIZE;

    int32_t rand_state = RAND_status();
    if (rand_state != GMSSL_OK) {
        tloge("RAND status is failed!\n");
        TEE_GenerateRandom(rand_seed, rand_seed_size);
        RAND_seed((const void *)rand_seed, (int32_t)rand_seed_size);
    }
}

static int32_t sm2_sig_to_buff(const ECDSA_SIG *sig, uint8_t *signature, uint32_t *signature_len)
{
    int32_t ret = CRYPTO_ERROR_SECURITY;

    bool check = (*signature_len < SIG_COMPONENT_SIZE * SIG_COMPONENT_NUM ||
        BN_num_bytes(sig->r) > SIG_COMPONENT_SIZE || BN_num_bytes(sig->s) > SIG_COMPONENT_SIZE);
    if (check) {
        tloge("the out buff is too small\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    uint8_t *r = TEE_Malloc(SIG_COMPONENT_SIZE, 0);
    if (r == NULL) {
        tloge("malloc failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    uint8_t *s = TEE_Malloc(SIG_COMPONENT_SIZE, 0);
    if (s == NULL) {
        tloge("malloc failed\n");
        goto exit;
    }

    int32_t len_r = BN_bn2bin(sig->r, r + SIG_COMPONENT_SIZE - BN_num_bytes(sig->r));
    if (len_r <= 0) {
        tloge("bn to bin failed r length = %d\n", len_r);
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto exit;
    }

    int32_t len_s = BN_bn2bin(sig->s, s + SIG_COMPONENT_SIZE - BN_num_bytes(sig->s));
    if (len_s <= 0) {
        tloge("bn to bin failed s length = %d\n", len_s);
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto exit;
    }

    if (memcpy_s(signature, *signature_len, r, SIG_COMPONENT_SIZE) != EOK) {
        tloge("memcpy failed\n");
        goto exit;
    }

    if (memcpy_s(signature + SIG_COMPONENT_SIZE, *signature_len - SIG_COMPONENT_SIZE, s, SIG_COMPONENT_SIZE) != EOK) {
        tloge("memcpy failed\n");
        goto exit;
    }

    *signature_len = SIG_COMPONENT_SIZE * SIG_COMPONENT_NUM;
    ret = CRYPTO_SUCCESS;
exit:
    TEE_Free(s);
    s = NULL;
    TEE_Free(r);
    return ret;
}

static int32_t sm2_sign_new_level(const uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len, const EC_KEY *ec_key)
{
    if (*signature_len < SM2_SIG_LEN) {
        tloge("output buffer is not large enough! signature length= %u\n", *signature_len);
        return CRYPTO_NOT_SUPPORTED;
    }
    if (digest_len != SM2_DIGEST_LEN) {
        tloge("digest len is not 32 bytes! digest_len = %u bytes\n", digest_len);
        return CRYPTO_BAD_PARAMETERS;
    }

    gmssl_generate_random();

    ECDSA_SIG *sig = NULL;
    int32_t ret;

    ret = sm2_sign(digest, digest_len, signature, signature_len, (EC_KEY *)ec_key);
    if (ret != GMSSL_OK) {
        tloge("SM2 sign failed\n");
        goto exit;
    }
    sig = ECDSA_SIG_new();
    if (d2i_ECDSA_SIG(&sig, (const unsigned char **)&signature, *signature_len) == NULL) {
        tloge("SM2 sign failed\n");
        goto exit;
    }
    signature -= *signature_len;
    ret = sm2_sig_to_buff(sig, signature, signature_len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("sm2 sign change format failed\n");
        goto exit;
    }
exit:
    ECDSA_SIG_free(sig);
    return ret;
}

static int32_t sm2_sign_old_level(const uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len, const EC_KEY *ec_key)
{
    if (*signature_len < SM2_SIGN_MAX) {
        tloge("output buffer is not large enough! signature length= %u\n", *signature_len);
        return CRYPTO_NOT_SUPPORTED;
    }

    gmssl_generate_random();

    int32_t ret = sm2_sign(digest, digest_len, signature, signature_len, (EC_KEY *)ec_key);
    if (ret != GMSSL_OK) {
        tloge("SM2 sign failed\n");
        return get_soft_crypto_error(CRYPTO_SIGNATURE_INVALID);
    }

    return CRYPTO_SUCCESS;
}

static int32_t tee_sm2_sign(const uint8_t *digest, uint32_t digest_len,
        uint8_t *signature, uint32_t *signature_len, const EC_KEY *ec_key)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level > API_LEVEL1_0)
        return sm2_sign_new_level(digest, digest_len, signature, signature_len, ec_key);
    else
        return sm2_sign_old_level(digest, digest_len, signature, signature_len, ec_key);
}

static int32_t sm2_buff_to_sig(const uint8_t *signature, uint32_t signature_len, ECDSA_SIG **sig)
{
    /* sig will be free in the caller function */
    if (*sig == NULL) {
        tloge("get ECDSA SIG failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    (*sig)->r = BN_new();
    if ((*sig)->r == NULL) {
        tloge("init signature failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    (*sig)->s = BN_new();
    if ((*sig)->s == NULL) {
        tloge("init signature failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    if (BN_bin2bn(signature, SIG_COMPONENT_SIZE, (*sig)->r) == NULL) {
        tloge("get r failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    if (BN_bin2bn(signature + SIG_COMPONENT_SIZE, signature_len - SIG_COMPONENT_SIZE, (*sig)->s) == NULL) {
        tloge("get s failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    return CRYPTO_SUCCESS;
}

static int32_t sm2_verify_new_level(const uint8_t *digest, uint32_t digest_len,
        const uint8_t *signature, uint32_t signature_len, const EC_KEY *ec_key)
{
    if (signature_len != SM2_SIG_LEN) {
        tloge("output buffer is too large, signature length = %u!\n", signature_len);
        return TEE_ERROR_SHORT_BUFFER;
    }
    int32_t rc;
    ECDSA_SIG *sig = NULL;
    size_t temp_len_src = signature_len + DEST_DATA_TEMP;
    uint8_t *temp_data_src = TEE_Malloc(temp_len_src, 0);
    if (temp_data_src == NULL)
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    gmssl_generate_random();

    sig = ECDSA_SIG_new();
    rc = sm2_buff_to_sig(signature, signature_len, &sig);
    if (rc != CRYPTO_SUCCESS) {
        tloge("get sm2 sig failed\n");
        goto exit;
    }
    temp_len_src = i2d_ECDSA_SIG(sig, &temp_data_src);
    temp_data_src -= temp_len_src;

    rc = sm2_verify(digest, digest_len, temp_data_src, temp_len_src, (EC_KEY *)ec_key);
    if (rc != GMSSL_OK) {
        tloge("SM2 verify failed\n");
        rc = CRYPTO_SIGNATURE_INVALID;
        goto exit;
    }
    rc = CRYPTO_SUCCESS;
exit:
    ECDSA_SIG_free(sig);
    (void)memset_s(temp_data_src, temp_len_src, 0, temp_len_src);
    TEE_Free(temp_data_src);
    return rc;
}

static int32_t sm2_verify_old_level(const uint8_t *digest, uint32_t digest_len,
    const uint8_t *signature, uint32_t signature_len, const EC_KEY *ec_key)
{
    int32_t rc;

    if (signature_len > SM2_SIGN_MAX) {
        tloge("output buffer is too large , signature length = %u!\n", signature_len);
        return TEE_ERROR_SHORT_BUFFER;
    }

    rc = sm2_verify(digest, digest_len, signature, signature_len, (EC_KEY *)ec_key);
    if (rc != GMSSL_OK) {
        tloge("SM2 verify failed\n");
        rc = get_soft_crypto_error(CRYPTO_SIGNATURE_INVALID);
        goto exit;
    }
    rc = CRYPTO_SUCCESS;
exit:
    return rc;
}

static int32_t tee_sm2_verify(const uint8_t *digest, uint32_t digest_len,
    const uint8_t *signature, uint32_t signature_len, const EC_KEY *ec_key)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level > API_LEVEL1_0)
        return sm2_verify_new_level(digest, digest_len, signature, signature_len, ec_key);
    else
        return sm2_verify_old_level(digest, digest_len, signature, signature_len, ec_key);
}

static void sm2_new_ec_group_free(struct ec_key_pair_bignum_t *ec_key_pair_bignum, bool flag)
{
    BN_CTX_free(ec_key_pair_bignum->ctx);
    ec_key_pair_bignum->ctx = NULL;
    BN_free(ec_key_pair_bignum->big_p);
    ec_key_pair_bignum->big_p = NULL;
    BN_free(ec_key_pair_bignum->big_a);
    ec_key_pair_bignum->big_a = NULL;
    BN_free(ec_key_pair_bignum->big_b);
    ec_key_pair_bignum->big_b = NULL;
    BN_free(ec_key_pair_bignum->big_x);
    ec_key_pair_bignum->big_x = NULL;
    BN_free(ec_key_pair_bignum->big_y);
    ec_key_pair_bignum->big_y = NULL;
    BN_free(ec_key_pair_bignum->big_n);
    ec_key_pair_bignum->big_n = NULL;
    BN_free(ec_key_pair_bignum->big_h);
    ec_key_pair_bignum->big_h = NULL;
    EC_POINT_free(ec_key_pair_bignum->point);
    ec_key_pair_bignum->point = NULL;
    if (flag && (ec_key_pair_bignum->group != NULL)) {
        EC_GROUP_free(ec_key_pair_bignum->group);
        ec_key_pair_bignum->group = NULL;
    }
}

static int32_t sm2_new_group_prime_field(struct ec_key_pair_bignum_t *ec_key_pair_bignum)
{
    ec_key_pair_bignum->group = EC_GROUP_new_curve_GFp(ec_key_pair_bignum->big_p, ec_key_pair_bignum->big_a,
        ec_key_pair_bignum->big_b, ec_key_pair_bignum->ctx);
    if (ec_key_pair_bignum->group == NULL)
        return GMSSL_ERR;

    ec_key_pair_bignum->point = EC_POINT_new(ec_key_pair_bignum->group);
    if (ec_key_pair_bignum->point == NULL)
        return GMSSL_ERR;

    return EC_POINT_set_affine_coordinates_GFp(ec_key_pair_bignum->group, ec_key_pair_bignum->point,
        ec_key_pair_bignum->big_x, ec_key_pair_bignum->big_y, ec_key_pair_bignum->ctx);
}

static int32_t sm2_new_group_other_field(struct ec_key_pair_bignum_t *ec_key_pair_bignum)
{
    ec_key_pair_bignum->group = EC_GROUP_new_curve_GF2m(ec_key_pair_bignum->big_p, ec_key_pair_bignum->big_a,
        ec_key_pair_bignum->big_b, ec_key_pair_bignum->ctx);
    if (ec_key_pair_bignum->group == NULL)
        return GMSSL_ERR;

    ec_key_pair_bignum->point = EC_POINT_new(ec_key_pair_bignum->group);
    if (ec_key_pair_bignum->point == NULL)
        return GMSSL_ERR;

    return EC_POINT_set_affine_coordinates_GF2m(ec_key_pair_bignum->group, ec_key_pair_bignum->point,
        ec_key_pair_bignum->big_x, ec_key_pair_bignum->big_y, ec_key_pair_bignum->ctx);
}

static EC_GROUP *sm2_new_ec_group(int is_prime_field, const struct sm2_new_ec_group_t *ec_group_t)
{
    int ret;
    bool check = true;
    struct ec_key_pair_bignum_t ec_key_pair_bignum = {0};

    ec_key_pair_bignum.ctx = BN_CTX_new();
    if (ec_key_pair_bignum.ctx == NULL)
        goto err;

    check = (ec_group_t == NULL || BN_hex2bn(&(ec_key_pair_bignum.big_p), (ec_group_t->p_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_a), (ec_group_t->a_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_b), (ec_group_t->b_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_x), (ec_group_t->x_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_y), (ec_group_t->y_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_n), (ec_group_t->n_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_h), (ec_group_t->h_hex)) == 0);
    if (check)
        goto err;

    if (is_prime_field)
        ret = sm2_new_group_prime_field(&ec_key_pair_bignum);
    else
        ret = sm2_new_group_other_field(&ec_key_pair_bignum);
    if (ret == GMSSL_ERR)
        goto err;

    if (EC_GROUP_set_generator(ec_key_pair_bignum.group, ec_key_pair_bignum.point,
        ec_key_pair_bignum.big_n, ec_key_pair_bignum.big_h) == 0)
        goto err;
    EC_GROUP_set_asn1_flag(ec_key_pair_bignum.group, 0);
    EC_GROUP_set_point_conversion_form(ec_key_pair_bignum.group, POINT_CONVERSION_UNCOMPRESSED);

    check = false;
err:
    sm2_new_ec_group_free(&ec_key_pair_bignum, check);
    return ec_key_pair_bignum.group;
}

static int32_t set_sm2_pub_key(EC_KEY *ec_key, BIGNUM **x, BIGNUM **y, const char *x_p, const char *y_p)
{
    bool check = (BN_hex2bn(x, x_p) == GMSSL_ERR || BN_hex2bn(y, y_p) == GMSSL_ERR ||
        EC_KEY_set_public_key_affine_coordinates(ec_key, *x, *y) == GMSSL_ERR);
    if (check) {
        tloge("set sm2 pub key failed\n");
        return GMSSL_ERR;
    }
    return GMSSL_OK;
}

static EC_KEY *sm2_new_ec_key(const EC_GROUP *group, const char *sk, const char *x_p, const char *y_p)
{
    int ok    = 0;
    BIGNUM *d = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    if (group == NULL) {
        tloge("parameter is NULL!\n");
        return NULL;
    }
    EC_KEY *ec_key = EC_KEY_new();
    if (ec_key == NULL)
        return NULL;

    int32_t ret = EC_KEY_set_group(ec_key, group);
    if (ret == GMSSL_ERR) {
        tloge("openssl: set key failed\n");
        goto end;
    }

    if (sk != NULL) {
        ret = BN_hex2bn(&d, sk);
        if (ret == GMSSL_ERR) {
            tloge("openssl:get bn failed\n");
            goto end;
        }

        ret = EC_KEY_set_private_key(ec_key, d);
        if (ret == GMSSL_ERR) {
            tloge("openssl:set private key failed\n");
            goto end;
        }
    }

    bool check = (x_p != NULL) && (y_p != NULL);
    if (check) {
        ret = set_sm2_pub_key(ec_key, &x, &y, x_p, y_p);
        if (ret == GMSSL_ERR)
            goto end;
    }

    ok = 1;
end:
    BN_free(d);
    d = NULL;
    BN_free(x);
    x = NULL;
    BN_free(y);
    y = NULL;
    if ((ok == 0) && (ec_key != NULL)) {
        EC_KEY_free(ec_key);
        ec_key = NULL;
    }
    return ec_key;
}

static TEE_Result sm2_buf2hexstr(const unsigned char *buffer, uint32_t len, char *out, uint32_t out_len)
{
    bool check = (buffer == NULL || out == NULL || len == 0);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    static const char hexdig[] = "0123456789ABCDEF";
    uint8_t *q                 = NULL;
    const unsigned char *p     = NULL;
    uint32_t i;

    if (out_len < (len << 1)) {
        tloge("out_len is not large enough!");
        return CRYPTO_BAD_PARAMETERS;
    }

    q = (uint8_t *)out;
    for (i = 0, p = buffer; i < len; i++, p++) {
        *q++ = hexdig[(*p >> LOW_FOUR_BITS) & LOW_FOUR_BITS_MASK]; /* Shift right four digits */
        *q++ = hexdig[*p & LOW_FOUR_BITS_MASK];
    }
    return CRYPTO_SUCCESS;
}

static TEE_Result sm2_adapt_ec_key_buf(const char *src_buff, uint32_t src_buff_len,
    char *dest_buff, uint32_t dest_buff_len)
{
    if (dest_buff_len < src_buff_len) {
        tloge("The dest buff is too short\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t rc = memcpy_s(dest_buff + (dest_buff_len - src_buff_len), src_buff_len, src_buff, src_buff_len);
    if (rc != EOK) {
        tloge("memcpy error in fill zero to buff head\n");
        return TEE_ERROR_SECURITY;
    }
    if (src_buff_len == dest_buff_len)
        return CRYPTO_SUCCESS;
    rc = memset_s(dest_buff, dest_buff_len - src_buff_len, '0', dest_buff_len - src_buff_len);
    if (rc != EOK) {
        tloge("memset error in fill zero to buff head\n");
        return TEE_ERROR_SECURITY;
    }
    return CRYPTO_SUCCESS;
}

static int32_t sm2_get_dxy_bignum_to_buf(const struct ec_key_pair_bignum_t *ec_key_pair_bignum,
    struct memref_t *x, struct memref_t *y, struct memref_t *d)
{
    int32_t ret = 0;
    struct memref_t dd = {0};
    struct memref_t xx = {0};
    struct memref_t yy = {0};

    dd.buffer = (uintptr_t)BN_bn2hex(ec_key_pair_bignum->big_d);
    xx.buffer = (uintptr_t)BN_bn2hex(ec_key_pair_bignum->big_x);
    yy.buffer = (uintptr_t)BN_bn2hex(ec_key_pair_bignum->big_y);
    bool check = (dd.buffer == 0 || xx.buffer == 0 || yy.buffer == 0);
    if (check) {
        tloge("openssl:bn to buf failed!\n");
        ret = 0;
        goto end;
    }

    dd.size = strlen((const char *)(uintptr_t)dd.buffer);
    xx.size = strlen((const char *)(uintptr_t)xx.buffer);
    yy.size = strlen((const char *)(uintptr_t)yy.buffer);

    TEE_Result rc = sm2_adapt_ec_key_buf((const char *)(uintptr_t)xx.buffer, xx.size,
        (char *)(uintptr_t)x->buffer, KEY_SIZE_2);
    if (rc != CRYPTO_SUCCESS) {
        ret = 0;
        tloge("adapt ec key buf failed, buf_len=%u\n", xx.size);
        goto end;
    }
    rc = sm2_adapt_ec_key_buf((const char *)(uintptr_t)yy.buffer, yy.size, (char *)(uintptr_t)y->buffer, KEY_SIZE_2);
    if (rc != CRYPTO_SUCCESS) {
        ret = 0;
        tloge("adapt ec key buf failed, buf_len=%u\n", yy.size);
        goto end;
    }
    rc = sm2_adapt_ec_key_buf((const char *)(uintptr_t)dd.buffer, dd.size, (char *)(uintptr_t)d->buffer, KEY_SIZE_2);
    if (rc != CRYPTO_SUCCESS) {
        ret = 0;
        tloge("adapt ec key buf failed, buf_len=%u\n", dd.size);
        goto end;
    }

    ret = 1;
end:
    OPENSSL_free((void *)(uintptr_t)dd.buffer);
    dd.buffer = 0;
    OPENSSL_free((void *)(uintptr_t)xx.buffer);
    xx.buffer = 0;
    OPENSSL_free((void *)(uintptr_t)yy.buffer);
    yy.buffer = 0;
    return ret;
}

static void free_ec_key_pair_bignum(struct ec_key_pair_bignum_t *ec_key_pair_bignum)
{
    BN_free(ec_key_pair_bignum->big_x);
    ec_key_pair_bignum->big_x = NULL;
    BN_free(ec_key_pair_bignum->big_y);
    ec_key_pair_bignum->big_y = NULL;
    BN_CTX_free(ec_key_pair_bignum->ctx);
    ec_key_pair_bignum->ctx = NULL;
}

static int sm2_eckey_get_dxy(const EC_GROUP *group, const EC_KEY *ec_key,
                             const struct sm2_eckey_get_dxy_t *sm2_eckey_get_dxy_t)
{
    bool check = (group == NULL || ec_key == NULL || sm2_eckey_get_dxy_t == NULL || sm2_eckey_get_dxy_t->d == NULL ||
        sm2_eckey_get_dxy_t->x == NULL || sm2_eckey_get_dxy_t->y == NULL || sm2_eckey_get_dxy_t->d_len != KEY_SIZE_2 ||
        sm2_eckey_get_dxy_t->x_len != KEY_SIZE_2 || sm2_eckey_get_dxy_t->y_len != KEY_SIZE_2);
    if (check) {
        tloge("group or ec_key is NULL!\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct ec_key_pair_bignum_t ec_key_pair_bignum = {0};
    ec_key_pair_bignum.point = (EC_POINT *)EC_KEY_get0_public_key(ec_key);
    ec_key_pair_bignum.big_d = (BIGNUM *)EC_KEY_get0_private_key(ec_key);
    ec_key_pair_bignum.big_x  = BN_new();
    ec_key_pair_bignum.big_y  = BN_new();
    ec_key_pair_bignum.ctx = BN_CTX_new();

    check = (ec_key_pair_bignum.big_d == NULL || ec_key_pair_bignum.point == NULL || ec_key_pair_bignum.big_x == NULL ||
        ec_key_pair_bignum.big_y == NULL || ec_key_pair_bignum.ctx == NULL);
    if (check) {
        tloge("openssl:point or bigbum is NULL!\n");
        free_ec_key_pair_bignum(&ec_key_pair_bignum);
        return GMSSL_ERR;
    }

    int32_t sm2_ret = EC_POINT_get_affine_coordinates_GF2m(group, ec_key_pair_bignum.point,
        ec_key_pair_bignum.big_x, ec_key_pair_bignum.big_y, ec_key_pair_bignum.ctx);
    if (sm2_ret == GMSSL_ERR) {
        tloge("openssl:get ec params failed!\n");
        free_ec_key_pair_bignum(&ec_key_pair_bignum);
        return GMSSL_ERR;
    }

    struct memref_t dd = {0};
    struct memref_t xx = {0};
    struct memref_t yy = {0};

    dd.buffer = (uintptr_t)(sm2_eckey_get_dxy_t->d);
    dd.size = sm2_eckey_get_dxy_t->d_len;
    xx.buffer = (uintptr_t)(sm2_eckey_get_dxy_t->x);
    xx.size = sm2_eckey_get_dxy_t->x_len;
    yy.buffer = (uintptr_t)(sm2_eckey_get_dxy_t->y);
    yy.size = sm2_eckey_get_dxy_t->y_len;

    int32_t ret = sm2_get_dxy_bignum_to_buf(&ec_key_pair_bignum, &xx, &yy, &dd);
    free_ec_key_pair_bignum(&ec_key_pair_bignum);
    return ret;
}

static EC_KEY *new_ec_key(uint32_t group_type, const char *d, const char *x, const char *y)
{
    EC_GROUP *sm2_p256_group = NULL;
    EC_KEY *ec_key           = NULL;
    struct sm2_new_ec_group_t ec_group_t = {0};

    if (group_type == SM2_GROUP_NOSTANDARD) {
        ec_group_t.p_hex = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
        ec_group_t.a_hex = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
        ec_group_t.b_hex = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
        ec_group_t.x_hex = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
        ec_group_t.y_hex = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
        ec_group_t.n_hex = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
        ec_group_t.h_hex = "1";

        sm2_p256_group = sm2_new_ec_group(1, &ec_group_t);
    } else {
        sm2_p256_group = EC_GROUP_new_by_curve_name(NID_sm2);
    }
    if (sm2_p256_group == NULL) {
        tloge("sm2 new group failed!");
        return NULL;
    }

    ec_key = sm2_new_ec_key(sm2_p256_group, d, x, y);
    if (ec_key == NULL) {
        tloge("sm2_new_ec_key failed!\n");
        EC_GROUP_free(sm2_p256_group);
        return NULL;
    }
    EC_GROUP_free(sm2_p256_group);
    return ec_key;
}

static EC_KEY *get_sm2_pub_key(const void *key)
{
    struct ecc_pub_key_t *pubkey = (struct ecc_pub_key_t *)key;

    uint32_t api_level = tee_get_ta_api_level();
    if (api_level == API_LEVEL1_0) {
        if (pubkey->x_len != KEY_SIZE)
            return new_ec_key(pubkey->domain_id, NULL, (char *)pubkey->x, (char *)pubkey->y);
    }

    char x[KEY_SIZE_2 + STR_END_ZERO] = { 0 };
    char y[KEY_SIZE_2 + STR_END_ZERO] = { 0 };

    int32_t ret = (int32_t)sm2_buf2hexstr(pubkey->x, KEY_SIZE, x, KEY_SIZE_2 + STR_END_ZERO);
    if (ret != CRYPTO_SUCCESS) {
        tloge("buffer to hexstring failed!");
        return NULL;
    }

    ret = (int32_t)sm2_buf2hexstr(pubkey->y, KEY_SIZE, y, KEY_SIZE_2 + STR_END_ZERO);
    if (ret != CRYPTO_SUCCESS) {
        tloge("buffer to hexstring failed!");
        return NULL;
    }

    return new_ec_key(pubkey->domain_id, NULL, x, y);
}

static EC_KEY *get_sm2_priv_key(const void *key)
{
    struct ecc_priv_key_t *privkey = (struct ecc_priv_key_t *)key;

    uint32_t api_level = tee_get_ta_api_level();
    if (api_level == API_LEVEL1_0) {
        if (privkey->r_len != KEY_SIZE)
            return new_ec_key(privkey->domain_id, (const char *)privkey->r, NULL, NULL);
    }

    char d[KEY_SIZE_2 + STR_END_ZERO] = { 0 };
    int32_t ret = (int32_t)sm2_buf2hexstr(privkey->r, KEY_SIZE, d, KEY_SIZE_2 + STR_END_ZERO);
    if (ret != CRYPTO_SUCCESS) {
        tloge("buffer to hexstring failed!");
        return NULL;
    }

    return new_ec_key(privkey->domain_id, d, NULL, NULL);
}

static TEE_Result hexstr_to_buffer(char *str, uint32_t str_len)
{
    uint32_t buffer_size = str_len / STR_TO_HEX;
    TEE_Result ret;
    int32_t rc;

    uint8_t *buffer = TEE_Malloc(buffer_size, 0);
    if (buffer == NULL) {
        tloge("malloc failed!");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    char *temp_buffer = TEE_Malloc(STR_TO_HEX + 1, 0);
    if (temp_buffer == NULL) {
        tloge("malloc failed!");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto error_temp;
    }

    uint32_t j = 0;
    for (uint32_t i = 0; i < str_len; i += STR_TO_HEX) {
        rc = memcpy_s(temp_buffer, (STR_TO_HEX + 1), str + i, STR_TO_HEX);
        if (rc != EOK) {
            tloge("memcpy failed!");
            ret = TEE_ERROR_SECURITY;
            goto error;
        }
        buffer[j] = (uint8_t)strtol(temp_buffer, NULL, HEX_FLAG);
        j++;
    }

    rc = memcpy_s(str, str_len, buffer, buffer_size);
    if (rc != EOK) {
        tloge("memcpy failed!");
        ret = TEE_ERROR_SECURITY;
        goto error;
    }

    ret = CRYPTO_SUCCESS;
error:
    (void)memset_s(temp_buffer, STR_TO_HEX + 1, 0, STR_TO_HEX + 1);
    TEE_Free(temp_buffer);
    temp_buffer = NULL;
error_temp:
    (void)memset_s(buffer, buffer_size, 0, buffer_size);
    TEE_Free(buffer);
    buffer = NULL;
    return ret;
}

static EC_GROUP *get_ec_group(uint32_t group)
{
    EC_GROUP *sm2_p256_group = NULL;
    struct sm2_new_ec_group_t sm2_group = {0};

    if (group == SM2_GROUP_NOSTANDARD) {
        sm2_group.p_hex = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
        sm2_group.a_hex = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
        sm2_group.b_hex = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
        sm2_group.x_hex = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
        sm2_group.y_hex = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
        sm2_group.n_hex = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
        sm2_group.h_hex = "1";

        sm2_p256_group = sm2_new_ec_group(1, &sm2_group);
    } else {
        sm2_p256_group = EC_GROUP_new_by_curve_name(NID_sm2);
    }

    return sm2_p256_group;
}

static void eckey_get_dxy(struct sm2_eckey_get_dxy_t *sm2_eckey_struct, const sm2_key_pair *key_pair)
{
    sm2_eckey_struct->d = (char *)(key_pair->d);
    sm2_eckey_struct->d_len = KEY_SIZE_2;
    sm2_eckey_struct->x = (char *)(key_pair->x);
    sm2_eckey_struct->x_len = KEY_SIZE_2;
    sm2_eckey_struct->y = (char *)(key_pair->y);
    sm2_eckey_struct->y_len = KEY_SIZE_2;
}

static int32_t gen_sm2_keypair(uint32_t group, const sm2_key_pair *key_pair)
{
    int32_t ret;
    struct sm2_eckey_get_dxy_t sm2_eckey_struct = { 0 };

    gmssl_generate_random();

    /* new ec_key */
    EC_KEY *ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        tloge("EC KEY new failed!");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    /* Generate new group */
    EC_GROUP *sm2_p256_group = get_ec_group(group);
    if (sm2_p256_group == NULL) {
        tloge("SM2 new ec group failed!");
        ret =  get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto end;
    }

    /* set group to ec_key */
    if (EC_KEY_set_group(ec_key, sm2_p256_group) == GMSSL_ERR) {
        tloge("EC KEY set group failed");
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto end;
    }

    /* Generate new key */
    if (EC_KEY_generate_key(ec_key) == GMSSL_ERR) {
        tloge(" EC KEY generate keyfailed");
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto end;
    }

    /* get d, x, y from ec_key */
    eckey_get_dxy(&sm2_eckey_struct, key_pair);
    if (sm2_eckey_get_dxy(sm2_p256_group, ec_key, &sm2_eckey_struct) != GMSSL_OK) {
        tloge("SM2 EC KEY GET DXY keyfailed");
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto end;
    }
    ret = CRYPTO_SUCCESS;
end:
    EC_KEY_free(ec_key);
    ec_key = NULL;
    EC_GROUP_free(sm2_p256_group);
    return ret;
}

static int32_t copy_key_pair_to_object(struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key,
    const sm2_key_pair *key_pair, uint32_t mod_len, uint32_t key_len)
{
    bool check = (public_key->x_len < mod_len || public_key->y_len < mod_len || private_key->r_len < mod_len);
    if (check) {
        tloge("key size is invalid");
        return CRYPTO_SHORT_BUFFER;
    }
    if (memcpy_s(public_key->x, public_key->x_len, key_pair->x, key_len) != EOK) {
        tloge("[error]memcpy failed");
        return CRYPTO_ERROR_SECURITY;
    }
    public_key->x_len = key_len;

    if (memcpy_s(public_key->y, public_key->y_len, key_pair->y, key_len) != EOK) {
        tloge("[error]memcpy failed");
        return CRYPTO_ERROR_SECURITY;
    }
    public_key->y_len = key_len;

    if (memcpy_s(private_key->r, private_key->r_len, key_pair->d, key_len) != EOK) {
        tloge("[error]memcpy failed");
        return CRYPTO_ERROR_SECURITY;
    }
    private_key->r_len = key_len;

    return CRYPTO_SUCCESS;
}

static EC_KEY *creat_sm2_ec_key(const void *sm2_key, uint32_t mode)
{
    if (sm2_key == NULL) {
        tloge("params is invalid");
        return NULL;
    }

    switch (mode) {
    case ENC_MODE:
    case VERIFY_MODE:
        return get_sm2_pub_key(sm2_key);
    case DEC_MODE:
    case SIGN_MODE:
        return get_sm2_priv_key(sm2_key);
    default:
        tloge("bad params");
        return NULL;
    }
}

int32_t sm2_sign_verify(const void *sm2_key, uint32_t mode, const struct memref_t *digest,
    struct memref_t *signature)
{
    bool check = (sm2_key == NULL || digest == NULL || signature == NULL);
    if (check) {
        tloge("input is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    EC_KEY *ec_key = creat_sm2_ec_key(sm2_key, mode);
    if (ec_key == NULL) {
        tloge("create sm2 ec key failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    int32_t ret;
    if (mode == SIGN_MODE) {
        ret = tee_sm2_sign((uint8_t *)(uintptr_t)(digest->buffer), digest->size,
            (uint8_t *)(uintptr_t)(signature->buffer), &(signature->size), ec_key);
    } else if (mode == VERIFY_MODE) {
        ret = tee_sm2_verify((uint8_t *)(uintptr_t)(digest->buffer), digest->size,
            (uint8_t *)(uintptr_t)(signature->buffer), signature->size, ec_key);
    } else {
        tloge("invalid mode %u\n", mode);
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    EC_KEY_free(ec_key);
    return ret;
}

static TEE_Result cv_to_cip_check(const struct SM2_Ciphertext_st *cv, const uint32_t *len)
{
    if ((uint32_t)(cv->C3->length) >
        UINT32_MAX - COORDINATE_LEN * COORDINATE_NUM - SM2_CIPHER_START_LEN - cv->C2->length) {
        tloge("the out buffer is too small\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (*len < (uint32_t)(COORDINATE_LEN * COORDINATE_NUM + cv->C3->length +
        cv->C2->length + SM2_CIPHER_START_LEN)) {
        tloge("the out buffer is too small\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (BN_num_bytes(cv->C1x) > COORDINATE_LEN)
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);

    return CRYPTO_SUCCESS;
}

static int32_t copy_data_to_cipher(uint8_t *cipher, uint32_t *len, const uint8_t *x_buf, const uint8_t *y_buf,
    const struct SM2_Ciphertext_st *cv)
{
    if (memcpy_s(cipher + SM2_CIPHER_START_LEN, *len - SM2_CIPHER_START_LEN, x_buf, COORDINATE_LEN) != EOK)
        return CRYPTO_ERROR_SECURITY;

    if (memcpy_s(cipher + SM2_CIPHER_START_LEN + COORDINATE_LEN, *len - SM2_CIPHER_START_LEN - COORDINATE_LEN,
        y_buf, COORDINATE_LEN) != EOK)
        return CRYPTO_ERROR_SECURITY;
    if (memcpy_s(cipher + COORDINATE_LEN * COORDINATE_NUM + SM2_CIPHER_START_LEN,
        *len - COORDINATE_LEN * COORDINATE_NUM - SM2_CIPHER_START_LEN,
        cv->C3->data, cv->C3->length) != EOK)
        return CRYPTO_ERROR_SECURITY;
    if (memcpy_s(cipher + COORDINATE_LEN * COORDINATE_NUM + cv->C3->length + SM2_CIPHER_START_LEN,
        *len - COORDINATE_LEN * COORDINATE_NUM - cv->C3->length - SM2_CIPHER_START_LEN,
        cv->C2->data, cv->C2->length) != EOK)
        return CRYPTO_ERROR_SECURITY;

    *len = COORDINATE_LEN * COORDINATE_NUM + cv->C3->length + cv->C2->length + SM2_CIPHER_START_LEN;
    return CRYPTO_SUCCESS;
}

static TEE_Result cv_to_cip(const struct SM2_Ciphertext_st *cv, uint8_t *cipher, uint32_t *len)
{
    cipher[0]                     = SM2_CIPHER_START;
    uint8_t x_buf[COORDINATE_LEN] = { 0 };
    uint8_t y_buf[COORDINATE_LEN] = { 0 };

    TEE_Result ret = cv_to_cip_check(cv, len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("cv to cip check failed\n");
        return ret;
    }

    int32_t x_len = BN_bn2bin(cv->C1x,
                              x_buf + COORDINATE_LEN - BN_num_bytes(cv->C1x));
    if (x_len <= 0) {
        tloge("get x coordinate failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    int32_t y_len = BN_bn2bin(cv->C1y,
                              y_buf + COORDINATE_LEN - BN_num_bytes(cv->C1y));
    if (y_len <= 0) {
        tloge("get y coordinate failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    return (TEE_Result)copy_data_to_cipher(cipher, len, x_buf, y_buf, cv);
}

static int32_t do_sm2_encrypt(const EC_KEY *ec_key, const uint8_t *src_data, uint32_t src_len,
    uint8_t *dest_data, uint32_t *dest_len)
{
    int32_t ret;
    size_t temp_len = (size_t)*dest_len;
    struct SM2_Ciphertext_st *cv = NULL;

    if (src_len > SM2_MAX_PLAINTEXT_LENGTH) {
        tloge("srcLen is too big!");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (*dest_len < (src_len + SM2_INCREASE_MAX)) {
        tloge("destLen is not large enough to hold the result!");
        return CRYPTO_SHORT_BUFFER;
    }

    gmssl_generate_random();

    /* use publicKey to encrypt */
    ret = sm2_encrypt(ec_key, EVP_sm3(), src_data, src_len, dest_data, &temp_len);
    if (ret != GMSSL_OK) {
        tloge("SM2 do encrypt failed");
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto out;
    }

    /* pass cv to destData */
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level > API_LEVEL1_0) {
        cv = d2i_SM2_Ciphertext(NULL, (const unsigned char **)&dest_data, temp_len);
        dest_data -= temp_len;
        if (cv == NULL) {
            tloge("SM2 do encrypt failed");
            ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
            goto out;
        }
        ret = cv_to_cip(cv, dest_data, (uint32_t *)&temp_len);
        if (ret != CRYPTO_SUCCESS) {
            tloge("get final data failed\n");
            goto out;
        }
    }
    *dest_len = (uint32_t)temp_len;
    ret = CRYPTO_SUCCESS;
out:
    SM2_Ciphertext_free(cv);
    return ret;
}

static TEE_Result cip_to_cv(const uint8_t *cipher, uint32_t len, struct SM2_Ciphertext_st *cv)
{
    int32_t rc;

    bool check = (BN_bin2bn(cipher + SM2_CIPHER_START_LEN, COORDINATE_LEN, cv->C1x) == NULL);
    if (check) {
        tloge("get C1 x failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    check = (BN_bin2bn(cipher + COORDINATE_LEN + SM2_CIPHER_START_LEN, COORDINATE_LEN, cv->C1y) == NULL);
    if (check) {
        tloge("get C1 y failed\n");
        return  get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    rc = ASN1_OCTET_STRING_set(cv->C3, cipher + COORDINATE_LEN * COORDINATE_NUM + SM2_CIPHER_START_LEN, HASH_SIZE);
    if (rc != GMSSL_OK) {
        tloge("get hash failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    rc = ASN1_OCTET_STRING_set(cv->C2,
                               cipher + COORDINATE_LEN * COORDINATE_NUM + HASH_SIZE + SM2_CIPHER_START_LEN,
                               len - COORDINATE_LEN * COORDINATE_NUM -  HASH_SIZE - SM2_CIPHER_START_LEN);
    if (rc != GMSSL_OK) {
        tloge("get cipher text failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    return CRYPTO_SUCCESS;
}

static int32_t pure_to_asn1(const uint8_t *src_data, const uint32_t src_len,
    uint8_t *dest_data, size_t *dest_len)
{
    int32_t ret;
    struct SM2_Ciphertext_st cv;
    cv.C1x = BN_new();
    cv.C1y = BN_new();
    cv.C2 = ASN1_OCTET_STRING_new();
    cv.C3 = ASN1_OCTET_STRING_new();
    if (cv.C1x == NULL || cv.C1y == NULL || cv.C2 == NULL || cv.C3 == NULL) {
        tloge("get cipher failed");
        ret = CRYPTO_CIPHERTEXT_INVALID;
        goto release;
    }
    ret = cip_to_cv(src_data, src_len, &cv);
    if (ret != CRYPTO_SUCCESS) {
        goto release;
    }
    /* return length or wrong num */
    int temp_len = i2d_SM2_Ciphertext(&cv, (unsigned char **)&dest_data);
    if (temp_len < CRYPTO_SUCCESS) {
        tloge("i2d_SM2_Ciphertext failed, res = %d", temp_len);
        goto release;
    }
    *dest_len = (size_t)temp_len;
release:
    BN_free(cv.C1x);
    cv.C1x = NULL;
    BN_free(cv.C1y);
    cv.C1y = NULL;
    ASN1_OCTET_STRING_free(cv.C2);
    cv.C2 = NULL;
    ASN1_OCTET_STRING_free(cv.C3);
    cv.C3 = NULL;
    return ret;
}

static int32_t sm2_decrypt_new(const EC_KEY *ec_key, const void *src_data, uint32_t src_len,
    void *dest_data, uint32_t *dest_len)
{
    TEE_Result ret;

    if (src_len < SM2_CIPHER_INCREASE || src_len >= UINT32_MAX - DEST_DATA_TEMP) {
        tloge("srcLen is invalid, src_len = %u\n", src_len);
        return CRYPTO_SHORT_BUFFER;
    }
    size_t temp_len = *dest_len;
    size_t temp_len_src = src_len + DEST_DATA_TEMP;
    uint8_t *temp_data_src = TEE_Malloc(temp_len_src, 0);
    if (temp_data_src == NULL)
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    gmssl_generate_random();

    ret = pure_to_asn1((uint8_t *)src_data, src_len, temp_data_src, &temp_len_src);
    if (ret != CRYPTO_SUCCESS)
        goto release;
    int32_t rc = sm2_decrypt(ec_key, EVP_sm3(), temp_data_src, temp_len_src, dest_data, &temp_len);
    bool check = (rc != GMSSL_OK || *dest_len < temp_len || temp_len > UINT32_MAX);
    if (check) {
        tloge("SM2 decrypt failed,rc = %d, temp_len = %u, dest_len = %u\n", rc, temp_len, *dest_len);
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto release;
    }
    *dest_len = (uint32_t)temp_len;
    ret = CRYPTO_SUCCESS;
release:
    (void)memset_s(temp_data_src, temp_len_src, 0, temp_len_src);
    TEE_Free(temp_data_src);
    return (int32_t)ret;
}

static int32_t sm2_decrypt_old(const EC_KEY *ec_key, const void *src_data, uint32_t src_len,
    void *dest_data, uint32_t *dest_len)
{
    int32_t ret;

    if (src_len < SM2_INCREASE_MIN) {
        tloge("srcLen is too small\n");
        return CRYPTO_SHORT_BUFFER;
    }

    if (*dest_len < (src_len - SM2_INCREASE_MIN)) {
        tloge("dest len is not large enough to hold the result!");
        return CRYPTO_SHORT_BUFFER;
    }

    size_t temp_dest_len = *dest_len;
    int32_t rc = sm2_decrypt(ec_key, EVP_sm3(), src_data, src_len, dest_data, &temp_dest_len);
    bool check = (rc != GMSSL_OK || temp_dest_len > UINT32_MAX);
    if (check) {
        tloge("SM2 decrypt failed\n");
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto release;
    }

    *dest_len = (uint32_t)temp_dest_len;
    ret = CRYPTO_SUCCESS;
release:
    return ret;
}

static int32_t do_sm2_decrypt(const EC_KEY *ec_key, const void *src_data, uint32_t src_len,
    void *dest_data, uint32_t *dest_len)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level > API_LEVEL1_0)
        return sm2_decrypt_new(ec_key, src_data, src_len, dest_data, dest_len);
    else
        return sm2_decrypt_old(ec_key, src_data, src_len, dest_data, dest_len);
}

int32_t sm2_encrypt_decypt(const void *sm2_key, uint32_t mode,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (sm2_key == NULL || data_in == NULL || data_in->buffer == 0 ||
                  data_out == NULL || data_out->buffer == 0);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    EC_KEY *ec_key = creat_sm2_ec_key(sm2_key, mode);
    if (ec_key == NULL) {
        tloge("input is NULL!");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    int32_t ret;
    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    if (mode == ENC_MODE) {
        ret = do_sm2_encrypt(ec_key, in_buffer, data_in->size, out_buffer, &(data_out->size));
    } else if (mode == DEC_MODE) {
        ret = do_sm2_decrypt(ec_key, in_buffer, data_in->size, out_buffer, &(data_out->size));
    } else {
        tloge("invalid mode %u\n", mode);
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    EC_KEY_free(ec_key);
    return ret;
}

static TEE_Result sm4_cipher_init_params_check(uint32_t alg_type, const struct memref_t *iv)
{
    bool check = (alg_type == TEE_ALG_SM4_CTR) || (alg_type == TEE_ALG_SM4_CBC_NOPAD) ||
                 (alg_type == TEE_ALG_SM4_CFB128) || (alg_type == TEE_ALG_SM4_CBC_PKCS7) ||
                 (alg_type == TEE_ALG_SM4_GCM);
    if (check) {
        bool check_iv = (iv == NULL || iv->buffer == 0 || iv->size == 0);
        if (check_iv) {
            tloge("IV is NULL, please set IV first\n");
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    return CRYPTO_SUCCESS;
}

static int32_t sm4_cbc_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx, uint8_t *key_buffer, uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_ecb_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx, uint8_t *key_buffer, uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_ctr_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx, uint8_t *key_buffer, uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_cfb_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx,
    const uint8_t *key_buffer, const uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sm4_cfb128(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sm4_cfb128(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_do_encrypt_init(EVP_CIPHER_CTX *ctx, uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    uint8_t *iv_buffer = NULL;
    bool check = (alg_type == TEE_ALG_SM4_CBC_NOPAD || alg_type == TEE_ALG_SM4_CTR) ||
                 (alg_type == TEE_ALG_SM4_CBC_PKCS7) || (alg_type == TEE_ALG_SM4_CFB128);
    if (check)
        iv_buffer = (uint8_t *)(uintptr_t)(iv->buffer);
    uint8_t *key_buffer = (uint8_t *)(uintptr_t)(key->key_buffer);

    switch (alg_type) {
    case TEE_ALG_SM4_CBC_NOPAD:
    case TEE_ALG_SM4_CBC_PKCS7:
        return sm4_cbc_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    case TEE_ALG_SM4_ECB_NOPAD:
        return sm4_ecb_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    case TEE_ALG_SM4_CTR:
        return sm4_ctr_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    case TEE_ALG_SM4_CFB128:
        return sm4_cfb_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    default:
        return GMSSL_ERR;
    }
}

void *tee_sm4_cipher_init(uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    int32_t ret;
    TEE_Result ret_c;
    bool check = (key == NULL || key->key_buffer == 0 || key->key_size == 0);
    if (check) {
        tloge("keybuf is NULL");
        return NULL;
    }

    ret_c = sm4_cipher_init_params_check(alg_type, iv);
    if (ret_c != CRYPTO_SUCCESS) {
        tloge("check iv failed\n");
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        tloge("New SM4 ctx failed");
        return NULL;
    }
    ret = EVP_CIPHER_CTX_reset(ctx);
    if (ret != 1) {
        tloge("init SM4 ctx failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    ret = sm4_do_encrypt_init(ctx, alg_type, direction, key, iv);
    if (ret != 1)
        goto exit;

    if (alg_type == TEE_ALG_SM4_CBC_PKCS7)
        (void)EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    else
        (void)EVP_CIPHER_CTX_set_padding(ctx, 0);
    return ctx;

exit:
    tloge("EVP sm4 cipher init failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

int32_t sm4_cipher_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key, const struct memref_t *iv)
{
    bool check = (ctx == NULL || key == NULL || key->key_buffer == 0 || key->key_size == 0);
    if (check) {
        tloge("input is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    void *sm4_ctx = tee_sm4_cipher_init(ctx->alg_type, ctx->direction, key, iv);
    if (sm4_ctx == NULL) {
        tloge("sm4 init failed");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    ctx->ctx_buffer = (uint64_t)(uintptr_t)sm4_ctx;
    ctx->free_context = free_sm4_context;
    return CRYPTO_SUCCESS;
}

static int32_t sm4_update_params_check(uint32_t alg_type, uint32_t src_len, uint32_t dest_len)
{
    if (alg_type == TEE_ALG_SM4_CBC_PKCS7)
        return CRYPTO_SUCCESS;

    bool check = (alg_type == TEE_ALG_SM4_ECB_NOPAD) || (alg_type == TEE_ALG_SM4_CBC_NOPAD);
    if (check) {
        if ((src_len % SM4_BLOCK) != 0) {
            tloge("DataSize should be 16 bytes aligned!");
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    if (dest_len < src_len || dest_len == 0) {
        tloge("output buffer is too small\n");
        return CRYPTO_SHORT_BUFFER;
    }

    return CRYPTO_SUCCESS;
}

static int32_t tee_sm4_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    int32_t ret;

    EVP_CIPHER_CTX *sm4_ctx = (EVP_CIPHER_CTX *)(uintptr_t)ctx->ctx_buffer;
    if (sm4_ctx == NULL) {
        tloge("The sm4 cipher ctx is null");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    ret = sm4_update_params_check(ctx->alg_type, data_in->size, data_out->size);
    if (ret != CRYPTO_SUCCESS) {
        tloge("sm4 update parameter check failed\n");
        return ret;
    }

    if (data_out->size > INT32_MAX) {
        tloge("data out size is too long\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t temp_dest_len = (int32_t)data_out->size;
    if (ctx->direction == ENC_MODE)
        ret = EVP_EncryptUpdate(sm4_ctx, out_buffer, &temp_dest_len, in_buffer, data_in->size);
    else
        ret = EVP_DecryptUpdate(sm4_ctx, out_buffer, &temp_dest_len, in_buffer, data_in->size);
    if (ret != GMSSL_OK || temp_dest_len < 0) {
        tloge("sm4 cipher update failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    data_out->size = (uint32_t)temp_dest_len;
    return CRYPTO_SUCCESS;
}

int32_t sm4_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    bool check = (ctx == NULL || data_in == NULL || data_out == NULL ||
        ((ctx->alg_type != TEE_ALG_SM4_CBC_PKCS7 || ctx->direction == ENC_MODE) && data_out->size < data_in->size));
    if (check) {
        tloge("input is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    return tee_sm4_update(ctx, data_in, data_out);
}

static int32_t tee_sm4_do_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    int32_t ret;
    int32_t update_len = 0;
    uint32_t temp_len = data_out->size;
    if (data_in->buffer != 0 && data_in->size != 0) {
        ret = tee_sm4_update(ctx, data_in, data_out);
        if (ret != CRYPTO_SUCCESS) {
            tloge("sm4 update last block failed");
            EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer));
            ctx->ctx_buffer = 0;
            return ret;
        }
        update_len = (int32_t)data_out->size;
    }

    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    int32_t final_len = temp_len - update_len;
    if (ctx->direction == ENC_MODE)
        ret = EVP_EncryptFinal_ex((EVP_CIPHER_CTX *)(uintptr_t)ctx->ctx_buffer,
            out_buffer + update_len, &final_len);
    else
        ret = EVP_DecryptFinal_ex((EVP_CIPHER_CTX *)(uintptr_t)ctx->ctx_buffer,
            out_buffer + update_len, &final_len);
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer));
    ctx->ctx_buffer = 0;
    if (ret != 1) {
        tloge("sm4 cipher final failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    if (update_len > INT32_MAX - final_len) {
        tloge("final len is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = (uint32_t)(update_len + final_len);
    return CRYPTO_SUCCESS;
}

int32_t sm4_cipher_do_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    bool check = (ctx == NULL || data_in == NULL || data_out == NULL || data_out->buffer == 0 ||
                  data_out->size == 0 || data_out->size < data_in->size);
    if (check) {
        tloge("bad parameters\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    return tee_sm4_do_final(ctx, data_in, data_out);
}

static int32_t gen_sm2_key(sm2_key_pair **key_pair, uint32_t curve)
{
    *key_pair = TEE_Malloc(sizeof(sm2_key_pair), 0);
    if (*key_pair == NULL) {
        tloge("tee malloc failed1");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    int32_t ret = gen_sm2_keypair(curve, *key_pair);
    if (ret != CRYPTO_SUCCESS) {
        tloge("generate sm2 keypair failed!");
        (void)memset_s(*key_pair, sizeof(sm2_key_pair), 0, sizeof(sm2_key_pair));
        TEE_Free(*key_pair);
        *key_pair = NULL;
        return ret;
    }
    return 0;
}

static int32_t sm2_gen_keypair_new(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    int32_t ret;
    int32_t rc;
    bool check = (public_key == NULL || private_key == NULL || key_size != KEY_SIZE * BYTE_TO_BIT);
    if (check) {
        tloge("bad parameters");
        return CRYPTO_BAD_PARAMETERS;
    }

    sm2_key_pair *key_pair = NULL;
    ret = gen_sm2_key(&key_pair, curve);
    if (ret != CRYPTO_SUCCESS) {
        tloge("generate sm2 keypair failed!");
        return ret;
    }

    /* 64 byte hexstring to 32 byte buffer */
    ret = (int32_t)hexstr_to_buffer(key_pair->x, KEY_SIZE_2);
    if (ret != CRYPTO_SUCCESS) {
        tloge("openssl:get buffer failed\n");
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto end;
    }

    ret = (int32_t)hexstr_to_buffer(key_pair->y, KEY_SIZE_2);
    if (ret != CRYPTO_SUCCESS) {
        tloge("openssl:get buffer failed\n");
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto end;
    }

    ret = (int32_t)hexstr_to_buffer(key_pair->d, KEY_SIZE_2);
    if (ret != CRYPTO_SUCCESS) {
        tloge("openssl:get buffer failed\n");
        ret = get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        goto end;
    }

    ret = copy_key_pair_to_object(public_key, private_key, key_pair, KEY_SIZE, KEY_SIZE);
end:
    rc = memset_s(key_pair, sizeof(*key_pair), 0, sizeof(*key_pair));
    if (rc != EOK)
        tloge("memset keypair failed!");
    TEE_Free(key_pair);
    return ret;
}

static int32_t sm2_gen_keypair_old(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    (void)key_size;
    if (public_key == NULL || private_key == NULL) {
        tloge("input is null");
        return CRYPTO_BAD_PARAMETERS;
    }

    sm2_key_pair *key_pair = NULL;
    int32_t ret = gen_sm2_key(&key_pair, curve);
    if (ret != 0)
        return ret;

    ret = copy_key_pair_to_object(public_key, private_key, key_pair, MOD_LEN, KEY_SIZE_2);
    errno_t rc  = memset_s(key_pair, sizeof(*key_pair), 0, sizeof(*key_pair));
    if (rc != EOK)
        tloge("memset keypair failed!");
    TEE_Free(key_pair);
    return ret;
}

int32_t sm2_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    uint32_t api_leval = tee_get_ta_api_level();
    if (api_leval > API_LEVEL1_0)
        return sm2_gen_keypair_new(key_size, curve, public_key, private_key);
    else
        return sm2_gen_keypair_old(key_size, curve, public_key, private_key);
}

int32_t sm3_mac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key)
{
    bool check = (ctx == NULL || key == NULL || key->key_buffer == 0 || key->key_size == 0);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    if (hmac_ctx == NULL) {
        tloge("malloc failed!\n");
        return get_soft_crypto_error(CRYPTO_NOT_SUPPORTED);
    }

    if (HMAC_Init(hmac_ctx, (const unsigned char *)(uintptr_t)(key->key_buffer), key->key_size, EVP_sm3()) == 0) {
        tloge("sm3 hmac failed");
        HMAC_CTX_free(hmac_ctx);
        return get_soft_crypto_error(CRYPTO_MAC_INVALID);
    }
    ctx->ctx_buffer = (uint64_t)(uintptr_t)hmac_ctx;
    ctx->ctx_size = sizeof(*hmac_ctx);

    return CRYPTO_SUCCESS;
}

int32_t sm3_mac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    int32_t ret;
    bool check = (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL ||
        data_in->buffer == 0 || data_in->size == 0);
    if (check) {
        tloge("bad params\n");
        ret = CRYPTO_BAD_PARAMETERS;
        goto out;
    }

    if (HMAC_Update((HMAC_CTX *)(uintptr_t)(ctx->ctx_buffer),
                    (const unsigned char *)(uintptr_t)(data_in->buffer), data_in->size) == 0) {
        tloge("sm3 hmac failed");
        ret = get_soft_crypto_error(CRYPTO_MAC_INVALID);
        goto out;
    }
    return CRYPTO_SUCCESS;
out:
    if (ctx != NULL) {
        HMAC_CTX_free((HMAC_CTX *)(uintptr_t)ctx->ctx_buffer);
        ctx->ctx_buffer = 0;
    }
    return ret;
}

int32_t sm3_mac_computefinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    int32_t ret;
    if (ctx == NULL || ctx->ctx_buffer == 0)
        return CRYPTO_BAD_PARAMETERS;

    bool check = (data_out == NULL || data_out->buffer == 0 || data_out->size < SM3_DIGEST_LENGTH);
    if (check) {
        tloge("context is NULL");
        ret = CRYPTO_BAD_PARAMETERS;
        goto out;
    }

    uint32_t out_len = 0;
    if (HMAC_Final((HMAC_CTX *)(uintptr_t)(ctx->ctx_buffer),
                   (unsigned char *)(uintptr_t)data_out->buffer, &out_len) == 0) {
        tloge("sm3 hmac failed");
        ret = get_soft_crypto_error(CRYPTO_MAC_INVALID);
        goto out;
    }

    data_out->size = out_len;
    ret = CRYPTO_SUCCESS;
out:
    HMAC_CTX_free((HMAC_CTX *)(uintptr_t)ctx->ctx_buffer);
    ctx->ctx_buffer = 0;
    return ret;
}

int32_t sm3_digest_init(struct ctx_handle_t *ctx)
{
    if (ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    EVP_MD_CTX *sm3_ctx = EVP_MD_CTX_new();
    if (sm3_ctx == NULL) {
        tloge("malloc context failed!\n");
        return get_soft_crypto_error(CRYPTO_ERROR_OUT_OF_MEMORY);
    }

    if (EVP_DigestInit(sm3_ctx, EVP_sm3()) == 0) {
        tloge("sm3 init failed");
        EVP_MD_CTX_free(sm3_ctx);
        return get_soft_crypto_error(CRYPTO_MAC_INVALID);
    }

    ctx->ctx_buffer = (uint64_t)(uintptr_t)sm3_ctx;
    ctx->ctx_size = sizeof(*sm3_ctx);

    return CRYPTO_SUCCESS;
}

int32_t sm3_digest_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    int32_t ret;
    bool check = (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL ||
        data_in->buffer == 0 || data_in->size == 0);
    if (check) {
        tloge("Invalid params\n");
        ret = CRYPTO_BAD_PARAMETERS;
        goto out;
    }

    if (EVP_DigestUpdate((EVP_MD_CTX *)(uintptr_t)(ctx->ctx_buffer),
                         (const unsigned char *)(uintptr_t)data_in->buffer, (size_t)data_in->size) == 0) {
        tloge("sm3 hash update failed");
        ret = CRYPTO_MAC_INVALID;
        goto out;
    }

    return CRYPTO_SUCCESS;
out:
    if (ctx != NULL) {
        TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
        ctx->ctx_buffer = 0;
    }
    return ret;
}

int32_t sm3_digest_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    int32_t ret;
    bool check = (ctx == NULL || ctx->ctx_buffer == 0);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    check = (data_out == NULL || data_out->buffer == 0 || data_out->size < SM3_DIGEST_LENGTH);
    if (check) {
        tloge("context is NULL");
        ret = CRYPTO_BAD_PARAMETERS;
        goto out;
    }

    if (EVP_DigestFinal((EVP_MD_CTX *)(uintptr_t)(ctx->ctx_buffer),
                        (unsigned char *)(uintptr_t)(data_out->buffer), NULL) == 0) {
        tloge("do sm3 hash failed");
        ret = get_soft_crypto_error(CRYPTO_MAC_INVALID);
        goto out;
    }
    data_out->size = SM3_DIGEST_LENGTH;

    ret = CRYPTO_SUCCESS;

out:
    EVP_MD_CTX_free((EVP_MD_CTX *)(uintptr_t)ctx->ctx_buffer);
    ctx->ctx_buffer = 0;
    return ret;
}

static int32_t copy_sm_buf_info(uint64_t *dst_buf, const uint64_t src_buf, uint32_t src_size)
{
    TEE_Free((void *)(uintptr_t)*dst_buf);
    *dst_buf = 0;
    bool check = ((src_buf == 0) || (src_size == 0));
    if (check)
        return CRYPTO_SUCCESS;

    *dst_buf = (uint64_t)(uintptr_t)TEE_Malloc(src_size, TEE_MALLOC_FILL_ZERO);
    if (*dst_buf == 0) {
        tloge("dst_buf malloc failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    (void)memcpy_s((void *)(uintptr_t)*dst_buf, src_size, (void *)(uintptr_t)src_buf, src_size);

    return CRYPTO_SUCCESS;
}

static int32_t copy_sm4_operation(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    if (dest == NULL || src == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (dest->ctx_buffer != 0) {
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(dest->ctx_buffer));
        dest->ctx_buffer = 0;
    }
    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    EVP_CIPHER_CTX *new_ctx = EVP_CIPHER_CTX_new();
    if (new_ctx == NULL) {
        tloge("New aes ctx failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int32_t ret = EVP_CIPHER_CTX_copy(new_ctx, (EVP_CIPHER_CTX *)(uintptr_t)(src->ctx_buffer));
    if (ret != GMSSL_OK) {
        tloge("Copy aes ctx failed");
        EVP_CIPHER_CTX_free(new_ctx);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    dest->ctx_buffer = (uint64_t)(uintptr_t)new_ctx;

    return CRYPTO_SUCCESS;
}

int32_t soft_copy_gmssl_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    bool check = (dest == NULL || src == NULL);
    if (check) {
        tloge("Invalid params!\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    switch (src->alg_type) {
    case TEE_ALG_SM3:
        return copy_sm_buf_info(&(dest->ctx_buffer), src->ctx_buffer, sizeof(EVP_MD_CTX));
    case TEE_ALG_HMAC_SM3:
        return copy_sm_buf_info(&(dest->ctx_buffer), src->ctx_buffer, sizeof(HMAC_CTX));
    case TEE_ALG_SM4_ECB_NOPAD:
    case TEE_ALG_SM4_CBC_NOPAD:
    case TEE_ALG_SM4_CBC_PKCS7:
    case TEE_ALG_SM4_CTR:
    case TEE_ALG_SM4_CFB128:
    case TEE_ALG_SM4_GCM:
        return copy_sm4_operation(dest, src);
    default:
        return CRYPTO_SUCCESS;
    }
}

void free_sm4_context(uint64_t *ctx)
{
    bool check = (ctx == NULL || *ctx == 0);
    if (check) {
        tloge("Invalid params!\n");
        return;
    }

    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(*ctx));
    *ctx = 0;
}

int32_t crypto_sm3_hash(const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (data_in == NULL || data_out == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    struct ctx_handle_t ctx;
    int32_t rc = sm3_digest_init(&ctx);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 hash init failed");
        return get_soft_crypto_error(CRYPTO_ERROR_SECURITY);
    }

    rc = sm3_digest_update(&ctx, data_in);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 update failed");
        TEE_Free((void *)(uintptr_t)(ctx.ctx_buffer));
        return rc;
    }
    rc = sm3_digest_dofinal(&ctx, data_out);
    if (rc != CRYPTO_SUCCESS)
        tloge("sm3 dofinal failed");

    return rc;
}

int32_t crypto_sm3_hmac(const struct symmerit_key_t *key, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (key == NULL || data_in == NULL || data_out == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    struct ctx_handle_t ctx = {0};

    int32_t rc = sm3_mac_init(&ctx, key);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 hmac init failed");
        return get_soft_crypto_error(CRYPTO_ERROR_SECURITY);
    }

    rc = sm3_mac_update(&ctx, data_in);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 hmac init failed");
        TEE_Free((void *)(uintptr_t)(ctx.ctx_buffer));
        return get_soft_crypto_error(CRYPTO_ERROR_SECURITY);
    }

    rc = sm3_mac_computefinal(&ctx, data_out);
    if (rc != CRYPTO_SUCCESS)
        tloge("sm3 hmac dofinal failed");

    return rc;
}

