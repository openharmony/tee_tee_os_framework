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
#include <stdbool.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <rsa/rsa_local.h>
#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <securec.h>
#include <tee_log.h>
#include "ec_wrapper.h"
#include "crypto_inner_interface.h"
#include "soft_common_api.h"

/* ECC domain id defined in tomcrypto */
#define EC_KEY_FIX_BUFFER_LEN 66

#define OBJ_LEN_ONE 1
#define OBJ_LEN_TWO 2

int32_t ec_nid_tom2boringssl(uint32_t domain)
{
    switch (domain) {
    case NIST_P192:
        return NID_X9_62_prime192v1;
    case NIST_P224:
        return NID_secp224r1;
    case NIST_P256:
        return NID_X9_62_prime256v1;
    case NIST_P384:
        return NID_secp384r1;
    case NIST_P521:
        return NID_secp521r1;
    default:
        tloge("error domain %u", domain);
        return -1;
    }
}
static TEE_Result new_boring_ec_key(const BIGNUM *ecc_priv_boring, const EC_POINT *ecc_pub_boring,
    int32_t ec_nid, EC_KEY **eckey)
{
    EC_KEY *ecc_key = EC_KEY_new_by_curve_name(ec_nid);
    if (ecc_key == NULL) {
        tloge("soft_enine: %s\n", "new ecc key error");
        return TEE_ERROR_GENERIC;
    }
    if (EC_KEY_set_private_key(ecc_key, ecc_priv_boring) != 1) {
        tloge("set private key error");
        EC_KEY_free(ecc_key);
        return TEE_ERROR_GENERIC;
    }
    if (EC_KEY_set_public_key(ecc_key, ecc_pub_boring) != 1) {
        tloge("set pub key error");
        EC_KEY_free(ecc_key);
        return TEE_ERROR_GENERIC;
    }
    *eckey = ecc_key;
    return TEE_SUCCESS;
}

TEE_Result ecc_privkey_tee_to_boring(void *priv, void **eckey)
{
    BIGNUM *ecc_priv_boring  = NULL;
    EC_GROUP *group          = NULL;
    EC_POINT *ecc_pub_boring = NULL;
    ecc_priv_key_t *ecc_priv = NULL;
    int32_t boring_nid;
    TEE_Result ret;
    if (priv == NULL || eckey == NULL) {
        tloge("soft_enine: %s\n", "priv is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ecc_priv        = (ecc_priv_key_t *)priv;
    boring_nid      = (int32_t)ecc_priv->domain;
    ecc_priv_boring = BN_bin2bn(ecc_priv->r, ecc_priv->r_len, NULL);
    if (ecc_priv_boring == NULL) {
        tloge("soft_enine: %s\n", "bin2bn error in tee key to boring private key");
        return TEE_ERROR_GENERIC;
    }

    group = EC_GROUP_new_by_curve_name(boring_nid);
    if (group == NULL) {
        tloge("new ec group error");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    ecc_pub_boring = EC_POINT_new(group);
    if (ecc_pub_boring == NULL) {
        tloge("new boring pub error");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    int32_t res = EC_POINT_mul(group, ecc_pub_boring, ecc_priv_boring, NULL, NULL, NULL);
    if (res != 1) {
        tloge("POINT_mul error");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    ret = new_boring_ec_key(ecc_priv_boring, ecc_pub_boring, boring_nid, (EC_KEY **)eckey);
error:
    BN_free(ecc_priv_boring);
    EC_POINT_free(ecc_pub_boring);
    EC_GROUP_free(group);
    return ret;
}

TEE_Result ecc_pubkey_tee_to_boring(void *public_key, EC_KEY **eckey)
{
    ecc_pub_key_t *pub_key = (ecc_pub_key_t *)public_key;
    if (pub_key == NULL || eckey == NULL) {
        tloge("soft_enine: %s\n", "key is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(pub_key->domain);
    BIGNUM *x      = BN_bin2bn(pub_key->x, pub_key->x_len, NULL);
    BIGNUM *y      = BN_bin2bn(pub_key->y, pub_key->y_len, NULL);
    bool check     = (ec_key == NULL || x == NULL || y == NULL);
    if (check) {
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        tloge("bn new or create ec key error");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    int32_t res = EC_KEY_set_public_key_affine_coordinates(ec_key, x, y);
    if (res == 0) {
        tloge("set pub key error");
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    *eckey = ec_key;
    BN_free(x);
    BN_free(y);
    return TEE_SUCCESS;
}
static int32_t get_public_key(const ecc_priv_key_t *priv_info, struct ecc_derive_public_key_t *public_key)
{
    public_key->priv_bn = BN_bin2bn(priv_info->r, priv_info->r_len, NULL);
    if (public_key->priv_bn == NULL) {
        tloge("priv bin2bn failed");
        return -1;
    }

    public_key->pub_pt = EC_POINT_new(public_key->group);
    if (public_key->pub_pt == NULL) {
        tloge("pub new failed");
        return -1;
    }

    int32_t ret = EC_POINT_mul(public_key->group, public_key->pub_pt, public_key->priv_bn, NULL, NULL, public_key->ctx);
    if (ret != 1) {
        tloge("ec point mul failed");
        return -1;
    }

    ret = EC_POINT_get_affine_coordinates_GFp(public_key->group, public_key->pub_pt, public_key->x_bn, public_key->y_bn,
                                              public_key->ctx);
    if (ret != 1) {
        tloge("get pub point failed");
        return -1;
    }
    return ret;
}

int ecc_derive_public_key(ecc_priv_key_t *priv_info, ecc_pub_key_t *pub_info)
{
    bool check_flag = (priv_info == NULL || pub_info == NULL);
    if (check_flag) {
        tloge("soft_enine: %s\n", "invalid ec info");
        return -1;
    }

    int nid = ec_nid_tom2boringssl(priv_info->domain);
    if (nid < 0) {
        tloge("soft_enine: %s\n", "domain is error, bad private key");
        return -1;
    }

    struct ecc_derive_public_key_t public_key = {0};
    int ret = -1;
    public_key.group = EC_GROUP_new_by_curve_name(nid);
    if (public_key.group == NULL) {
        tloge("soft_enine: %s\n", "alloc group failed");
        return -1;
    }

    public_key.x_bn       = BN_new();
    public_key.y_bn       = BN_new();
    public_key.ctx        = BN_CTX_new();
    check_flag = (public_key.x_bn == NULL || public_key.y_bn == NULL || public_key.ctx == NULL);
    if (check_flag) {
        tloge("alloc points failed");
        goto error;
    }

    ret = get_public_key(priv_info, &public_key);
    if (ret != 1)
        goto error;

    pub_info->x_len  = (uint32_t)BN_bn2bin(public_key.x_bn, pub_info->x);
    pub_info->y_len  = (uint32_t)BN_bn2bin(public_key.y_bn, pub_info->y);
    pub_info->domain = priv_info->domain;
    ret              = 0;

error:
    /* boringssl API will check if pointer is NULL */
    BN_CTX_free(public_key.ctx);
    EC_POINT_free(public_key.pub_pt);
    BN_free(public_key.x_bn);
    BN_free(public_key.y_bn);
    BN_free(public_key.priv_bn);
    EC_GROUP_free(public_key.group);
    return ret;
}

int derive_ecc_private_key_from_huk(ecc_priv_key_t *priv, const uint8_t *secret, uint32_t sec_len)
{
    struct derive_ecc_private_key_from_huk_t priv_key = {0};
    int32_t ret = -1;

    if ((priv == NULL) || (secret == NULL) || (sec_len > SECRET_KEY_MAX_LEN)) {
        tloge("soft_enine: %s\n", "invalid params");
        return ret;
    }

    const uint8_t nist_p256_group_order[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
        0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    };

    priv_key.ord = BN_bin2bn(nist_p256_group_order, sizeof(nist_p256_group_order), NULL);
    if (priv_key.ord == NULL) {
        tloge("soft_enine: %s\n", "bin to bn error");
        return ret;
    }
    priv_key.x = BN_bin2bn(secret, sec_len, NULL);
    if (priv_key.x == NULL) {
        tloge("secret to bn fail");
        goto error;
    }
    if (BN_sub_word(priv_key.ord, 1) != 1) {
        tloge("ord get fail");
        goto error;
    }
    priv_key.ctx = BN_CTX_new();
    if (priv_key.ctx == NULL) {
        tloge("new ctx fail");
        goto error;
    }
    /* Compute x (mod (ord -1)) + 1 */
    ret = BN_mod(priv_key.x, priv_key.x, priv_key.ord, priv_key.ctx);
    BN_CTX_free(priv_key.ctx);
    priv_key.ctx = NULL;
    if ((ret != 1) || (BN_add_word(priv_key.x, 1) == 0)) {
        ret = -1;
        goto error;
    }
    priv->domain = NIST_P256;
    if (BN_num_bytes(priv_key.x) > ECC_PRIV_LEN) {
        ret = -1;
        goto error;
    }
    priv->r_len = (uint32_t)BN_bn2bin(priv_key.x, priv->r);
    ret         = 0;

error:
    BN_free(priv_key.x);
    BN_free(priv_key.ord);
    return ret;
}

/* file_name if rsa key, we can store offset by file_name */
int derive_private_key_from_secret(void *priv, uint8_t *secret, uint32_t secret_len, uint32_t bits, uint32_t key_type,
                                   uint8_t *file_name)
{
    /* file_name maybe null here */
    if (secret == NULL) {
        tloge("soft_enine: %s\n", "invalid params");
        return -1;
    }
    if (priv == NULL) {
        tloge("soft_enine: %s\n", "invalid params");
        return -1;
    }
    switch (key_type) {
    case RSA_ALG:
        return generate_rsa_from_secret(priv, bits, secret, secret_len, file_name);
    case ECC_ALG: {
        ecc_priv_key_t *priv_key = (ecc_priv_key_t *)priv;
        int ret;

        ret = derive_ecc_private_key_from_huk(priv_key, secret, secret_len);
        if (ret < 0) {
            tloge("soft_enine: %s\n", "derive ecc private fail");
            return -1;
        }
        return ret;
    }
    default:
        return -1;
    }
}
int32_t ecc_export_pub(uint8_t *out, uint32_t out_size, ecc_pub_key_t *pub)
{
    uint32_t old_domain;
    bool check = (out == NULL || pub == NULL);
    if (check) {
        tloge("soft_enine: %s\n", "ecc export pub input error");
        return -1;
    }
    old_domain     = pub->domain;
    int boring_cur = ec_nid_tom2boringssl(pub->domain);
    if (boring_cur < 0) {
        tloge("soft_enine: %s\n", "bad domain in ecc export pub");
        return -1;
    }
    pub->domain    = (uint32_t)boring_cur;
    EC_KEY *eckey  = NULL;
    TEE_Result ret = ecc_pubkey_tee_to_boring(pub, &eckey);
    pub->domain    = old_domain;
    if (ret != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "tee public key to boring key fail");
        return -1;
    }
    /* i2d_EC_PUBKEY while change tmp_out; */
    int32_t buffer_size = i2d_EC_PUBKEY(eckey, NULL);
    if ((uint32_t)buffer_size > out_size) {
        tloge("out buffer not enough");
        EC_KEY_free(eckey);
        return -1;
    }
    buffer_size = i2d_EC_PUBKEY(eckey, &out);
    EC_KEY_free(eckey);
    if (buffer_size == 0) {
        tloge("soft_enine: %s\n", "boring key to asn1 fail");
        return -1;
    }
    return buffer_size;
}
static TEE_Result ecc_get_domain_by_ec_key(const EC_KEY *key, uint32_t *domain)
{
    EC_GROUP *g = (EC_GROUP *)EC_KEY_get0_group(key);
    if (g == NULL) {
        tloge("soft_enine: %s\n", "EC KEY get group fail");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int cur                        = EC_GROUP_get_curve_name(g);
    uint32_t index                 = 0;
    crypto_u2u domain_to_curve_name[] = {
        { NID_X9_62_prime192v1, NIST_P192 }, { NID_secp224r1, NIST_P224 }, { NID_X9_62_prime256v1, NIST_P256 },
        { NID_secp384r1, NIST_P384 },        { NID_secp521r1, NIST_P521 },
    };
    for (; index < sizeof(domain_to_curve_name) / sizeof(crypto_u2u); index++) {
        if ((uint32_t)cur == domain_to_curve_name[index].src) {
            *domain = domain_to_curve_name[index].dest;
            return TEE_SUCCESS;
        }
    }
    tloge("get domain fail, invalid cur 0x%x\n", cur);
    return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result ecc_ecpubkey_boring_to_tee(const EC_KEY *key, ecc_pub_key_t *pub)
{
    if (key == NULL || pub == NULL) {
        tloge("soft_enine: %s\n", "input param is NULL");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret;
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (x == NULL || y == NULL) {
        tloge("new bn error in boring pub to tee pub");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto error;
    }
    const EC_POINT *point = EC_KEY_get0_public_key(key);
    if (point == NULL) {
        tloge("boring ec key get public key error");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    int32_t res = EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key), point, x, y, NULL);
    if (res == 0) {
        tloge("boring ec key get public x y error");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    uint32_t public_key_x_len = (uint32_t)BN_num_bytes(x);
    uint32_t public_key_y_len = (uint32_t)BN_num_bytes(y);
    if (public_key_x_len > EC_KEY_FIX_BUFFER_LEN || public_key_y_len > EC_KEY_FIX_BUFFER_LEN) {
        tloge("buffer not enough");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto error;
    }
    pub->x_len = (uint32_t)BN_bn2bin(x, pub->x);
    pub->y_len = (uint32_t)BN_bn2bin(y, pub->y);
    ret        = ecc_get_domain_by_ec_key(key, &pub->domain);
    if (ret != TEE_SUCCESS) {
        tloge("get domain fail");
        goto error;
    }
error:
    BN_free(x);
    BN_free(y);
    return ret;
}
int32_t ecc_import_pub(ecc_pub_key_t *pub, const uint8_t *in, uint32_t inlen)
{
    bool check = (pub == NULL || in == NULL);
    if (check) {
        tloge("soft_enine: %s\n", "ecc import pub in error");
        return -1;
    }
    EC_KEY *keyp             = NULL;
    const unsigned char *inp = (const unsigned char *)in;
    keyp                     = d2i_EC_PUBKEY(&keyp, &inp, inlen);
    if (keyp == NULL) {
        tloge("soft_enine: %s\n", "asn1 to ec public key fail");
        return -1;
    }
    TEE_Result ret = ecc_ecpubkey_boring_to_tee(keyp, pub);
    EC_KEY_free(keyp);
    keyp = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "boring ec key to tee fail");
        return -1;
    }
    return 1;
}
static TEE_Result ecc_priv_key_boring_to_tee(ecc_priv_key_t *priv, const EC_KEY *key)
{
    const BIGNUM *priv_bn = EC_KEY_get0_private_key(key);
    if (priv_bn == NULL) {
        tloge("soft_enine: %s\n", "ec key error, get private fail");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t domain = 0;
    TEE_Result ret  = ecc_get_domain_by_ec_key(key, &domain);
    if (ret != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "get domain by ec key fail");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    priv->domain             = domain;
    uint32_t private_key_len = (uint32_t)BN_num_bytes(priv_bn);
    if (private_key_len > EC_FIX_BUFFER_LEN) {
        tloge("soft_enine: %s\n", "private key to buffer error");
        return TEE_ERROR_GENERIC;
    }
    priv->r_len = (uint32_t)BN_bn2bin(priv_bn, priv->r);

    return TEE_SUCCESS;
}
int32_t ecc_import_priv(ecc_priv_key_t *priv, const uint8_t *in, uint32_t inlen)
{
    bool check = (priv == NULL || in == NULL);
    if (check) {
        tloge("soft_enine: %s\n", "ecc import priv in error");
        return -1;
    }
    EC_KEY *key        = NULL;
    const uint8_t *inp = in;
    key                = d2i_ECPrivateKey(&key, &inp, inlen);
    if (key == NULL) {
        tloge("soft_enine: %s\n", "asn1 to ec public key fail");
        return -1;
    }
    TEE_Result ret = ecc_priv_key_boring_to_tee(priv, key);
    EC_KEY_free(key);
    key = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "boring ec private key to tee fail");
        return -1;
    }

    return priv->r_len;
}

/* Read next TLV (Type-Length-Value) from ASN1 buffer buf
  @param type         [out] type of TLV
  @param header_len     [out] length of TLV
  @param buf         [in]  input TLV
  @param buf_len     [in]  Length of buf in bytes
  @Return length if next tlv can be found and otherwice -1.
 * */
int32_t get_next_tlv(uint32_t *type, uint32_t *header_len, const uint8_t *buf, uint32_t buf_len)
{
    uint32_t length = 0;
    if (type == NULL || header_len == NULL || buf == NULL) {
        tloge("soft_enine: %s\n", "get next tlv in error");
        return -1;
    }
    if (buf_len < CRYPTO_NUMBER_THREE) {
        tloge("soft_enine: %s\n", "buf_len too short.\n");
        return -1;
    }
    *type = buf[0];
    buf++;
    buf_len--;
    if (buf[0] < 0x80) { /* Current byte tells the length */
        length = (uint32_t)buf[0];
        buf++;
        buf_len--;
        *header_len = CRYPTO_NUMBER_TWO;
    } else {
        /* bit 8 is set */
        switch (buf[0] & 0x7F) {
        case OBJ_LEN_ONE: /* object length is one */
            buf++;
            length = (uint32_t)buf[0];
            buf++;
            buf_len -= CRYPTO_NUMBER_TWO;
            *header_len = CRYPTO_NUMBER_THREE;
            break;
        case OBJ_LEN_TWO: /* object length is two */
            if (buf_len < CRYPTO_NUMBER_THREE) {
                tloge("soft_enine: %s\n", "buf len is error");
                return -1;
            }
            buf_len -= CRYPTO_NUMBER_THREE;
            buf++;
            length = (((uint32_t)buf[0]) << CRYPTO_NUMBER_EIGHT) + (uint32_t)buf[1];
            *header_len = CRYPTO_NUMBER_FOUR;
            break;
        default: /* Object length does not make sense */
            return -1;
        }
    }
    /* Check that tag length can fit into buffer */
    if (length > buf_len) {
        tloge("soft_enine: %s\n", "get tlv buffer too short");
        return -1;
    }
    return length;
}

static int32_t get_ecsda_signature(ECDSA_SIG *sig_data, uint8_t *signature, uint32_t sig_size)
{
    uint8_t *outp    = NULL;
    int32_t sign_len = i2d_ECDSA_SIG(sig_data, &outp);
    OPENSSL_free(outp);
    if (sign_len < 0 || sign_len > (int32_t)sig_size) {
        tloge("out buffer too small");
        return -1;
    }
    outp = signature;
    return i2d_ECDSA_SIG(sig_data, &outp);
}

int32_t ecc_sign_digest(uint8_t *signature, uint32_t sig_size, uint8_t *in, uint32_t in_len, ecc_priv_key_t *priv)
{
    bool check = (signature == NULL || sig_size == 0 || (in == NULL && in_len != 0) || priv == NULL);
    if (check) {
        tloge("soft_enine: %s\n", "input param is NULL");
        return -1;
    }

    EC_KEY *eckey = NULL;
    int32_t cur = ec_nid_tom2boringssl(priv->domain);
    if (cur == -1) {
        tloge("soft_enine: %s\n", "cur get error");
        return -1;
    }
    uint32_t tmp_cur = priv->domain;
    priv->domain     = (uint32_t)cur;
    TEE_Result ret   = ecc_privkey_tee_to_boring(priv, (void **)&eckey);
    priv->domain     = tmp_cur;
    if (ret != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "Tee Private Key To Boring Key error");
        return -1;
    }
    ECDSA_SIG *sig_data = ECDSA_do_sign(in, in_len, eckey);
    EC_KEY_free(eckey);
    eckey = NULL;
    /* boring to asn */
    if (sig_data == NULL) {
        tloge("soft_enine: %s\n", "boring sign error");
        return -1;
    }
    int32_t sign_len = get_ecsda_signature(sig_data, signature, sig_size);
    ECDSA_SIG_free(sig_data);
#ifdef OPENSSL_ENABLE
    free_openssl_drbg_mem();
#endif

    return sign_len;
}
int32_t ecc_verify_digest(const uint8_t *signature, uint32_t sig_len, uint8_t *in, uint32_t in_len, ecc_pub_key_t *pub)
{
    bool check = (signature == NULL || sig_len == 0 || (in == NULL && in_len != 0) || pub == NULL);
    if (check) {
        tloge("soft_enine: %s\n", "input param is NULL");
        return -1;
    }

    ECDSA_SIG *outp    = NULL;
    const uint8_t *tmp = signature;
    EC_KEY *eckey      = NULL;
    int32_t ret;
    int cur = ec_nid_tom2boringssl(pub->domain);
    if (cur < 0) {
        tloge("soft_enine: %s\n", "get cur error");
        return -1;
    }
    outp = d2i_ECDSA_SIG(&outp, &tmp, sig_len);
    if (outp == NULL) {
        tloge("soft_enine: %s\n", "asn to boring fail, sign may be dx");
        return -1;
    }
    uint32_t tmp_cur = pub->domain;
    pub->domain      = (uint32_t)cur;
    ret              = (int32_t)ecc_pubkey_tee_to_boring(pub, &eckey);
    pub->domain      = tmp_cur;
    if (ret != 0) {
        ECDSA_SIG_free(outp);
        tloge("PubKeyToBoringKey key error");
        return -1;
    }
    ret = ECDSA_do_verify(in, in_len, outp, eckey);
    ECDSA_SIG_free(outp);
    outp = NULL;
    EC_KEY_free(eckey);
    eckey = NULL;
#ifdef OPENSSL_ENABLE
    free_openssl_drbg_mem();
#endif
    if (ret != 1) {
        tloge("soft_enine: %s\n", "boring verify error");
        return 0;
    }
    return 1;
}

