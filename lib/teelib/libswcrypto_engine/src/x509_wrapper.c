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
#include <string.h>
#include <tee_log.h>
#include <rsa/rsa_local.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <securec.h>
#include "crypto_wrapper.h"
#include "crypto_inner_interface.h"

static uint8_t g_rsa_key_oid[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static uint8_t g_ecc_key_oid[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1 };

int x509_crl_validate(uint8_t *cert, uint32_t cert_len, uint8_t *parent_key, uint32_t parent_key_len)
{
    X509_CRL *cert_x509 = NULL;
    EVP_PKEY *pkey      = NULL;
    int ret             = -1;

    if (cert == NULL || parent_key == NULL)
        return -1;

    cert_x509 = d2i_X509_CRL(NULL, (const uint8_t **)(&cert), (long)cert_len);
    if (cert_x509 == NULL) {
        tloge("d2i cert failed");
        goto error;
    }

    pkey = d2i_PUBKEY(&pkey, (const unsigned char **)(&parent_key), parent_key_len);
    if (pkey == NULL) {
        tloge("d2i pubkey failed");
        goto error;
    }

    ret = X509_CRL_verify(cert_x509, pkey);
error:
    X509_CRL_free(cert_x509);
    EVP_PKEY_free(pkey);

    return ret;
}
int x509_cert_validate(uint8_t *cert, uint32_t cert_len, uint8_t *parent_key, uint32_t parent_key_len)
{
    X509 *cert_x509 = NULL;
    EVP_PKEY *pkey  = NULL;
    int ret         = -1;

    if (cert == NULL || parent_key == NULL)
        return -1;

    cert_x509 = d2i_X509(NULL, (const unsigned char **)(&cert), (long)cert_len);
    if (cert_x509 == NULL) {
        tloge("d2i cert failed");
        goto error;
    }

    pkey = d2i_PUBKEY(&pkey, (const unsigned char **)(&parent_key), (long)parent_key_len);
    if (pkey == NULL) {
        tloge("d2i pubkey failed");
        goto error;
    }

    ret = X509_verify(cert_x509, pkey);

error:
    X509_free(cert_x509);
    EVP_PKEY_free(pkey);

    return ret;
}

int get_keytype_from_sp(const uint8_t *in, uint32_t inlen)
{
    int tag = 0;
    int class;
    long tmplen        = (long)inlen;
    const uint8_t *end = in + inlen;

    if (in == NULL)
        return -1;

    (void)ASN1_get_object(&in, &tmplen, &tag, &class, end - in);
    if (tag != V_ASN1_SEQUENCE) {
        tloge("tag1 invalid type");
        return -1;
    }

    tag = 0;
    end = in + tmplen;
    (void)ASN1_get_object(&in, &tmplen, &tag, &class, end - in);
    if (tag != V_ASN1_SEQUENCE) {
        tloge("tag2 invalid type");
        return -1;
    }

    tag = 0;
    end = in + tmplen;
    (void)ASN1_get_object(&in, &tmplen, &tag, &class, end - in);
    if (tag != V_ASN1_OBJECT) {
        tloge("tag1 invalid type");
        return -1;
    }

    if ((tmplen == (long)sizeof(g_rsa_key_oid)) && (memcmp(in, g_rsa_key_oid, tmplen) == 0))
        return RSA_ALG;
    if ((tmplen == (long)sizeof(g_ecc_key_oid)) && (memcmp(in, g_ecc_key_oid, tmplen) == 0))
        return ECC_ALG;

    /* It is not RSA nor ECC key */
    return -1;
}

static int ecc_nid_boringssl2tom(uint32_t nid)
{
    uint32_t index                 = 0;
    crypto_u2u nid_tom_to_boring[] = {
        { NID_X9_62_prime192v1, NIST_P192 }, { NID_secp224r1, NIST_P224 }, { NID_X9_62_prime256v1, NIST_P256 },
        { NID_secp384r1, NIST_P384 },        { NID_secp521r1, NIST_P521 },
    };
    for (; index < sizeof(nid_tom_to_boring) / sizeof(crypto_u2u); index++) {
        if (nid == nid_tom_to_boring[index].src)
            return nid_tom_to_boring[index].dest;
    }
    tloge("invalid nid 0x%x\n", nid);
    return -1;
}

static int get_rsa_pub_from_cert(rsa_pub_key_t *rsa_pub, const uint8_t *in, uint32_t inlen)
{
    RSA *rsa = NULL;
    uint32_t n_len, e_len;
    rsa     = d2i_RSA_PUBKEY(NULL, &in, inlen);
    if (rsa == NULL) {
        tloge("d2i rsa pubkey failed");
        return -1;
    }

    bool check = (rsa->e == NULL || rsa->n == NULL);
    if (check) {
        tloge("n or e is NULL");
        RSA_free(rsa);
        return -1;
    }

    n_len = (uint32_t)BN_num_bytes(rsa->n);
    e_len = (uint32_t)BN_num_bytes(rsa->e);
    if (n_len > sizeof(rsa_pub->n) || e_len > sizeof(rsa_pub->e)) {
        tloge("pub key buffer too small");
        RSA_free(rsa);
        return -1;
    }

    rsa_pub->n_len = (uint32_t)BN_bn2bin(rsa->n, rsa_pub->n);
    rsa_pub->e_len = (uint32_t)BN_bn2bin(rsa->e, rsa_pub->e);

    RSA_free(rsa);
    return 0;
}

static int get_ecc_pub_from_cert_helper(ecc_pub_key_t *ecc_pub, const EC_GROUP *group, const EC_POINT *point)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *ctx = NULL;
    int ret = -1;

    x = BN_new();
    y = BN_new();
    ctx = BN_CTX_new();
    if (x == NULL || y == NULL || ctx == NULL) {
        tloge("all bn ctx failed");
        goto clean;
    }

    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx) != 1) {
        tloge("all bn ctx failed");
        goto clean;
    }

    if ((uint32_t)BN_num_bytes(x) <= sizeof(ecc_pub->x) && (uint32_t)BN_num_bytes(y) <= sizeof(ecc_pub->y)) {
        ecc_pub->x_len = (uint32_t)BN_bn2bin(x, ecc_pub->x);
        ecc_pub->y_len = (uint32_t)BN_bn2bin(y, ecc_pub->y);
        ret = 0;
    } else {
        tloge("ec pub buffer too small");
    }

clean:
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);

    return ret;
}

static int get_ecc_pub_from_cert(ecc_pub_key_t *ecc_pub, const uint8_t *in, uint32_t inlen)
{
    EC_KEY *ec_key        = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *point = NULL;
    int ret               = -1;

    ec_key = d2i_EC_PUBKEY(NULL, &in, inlen);
    if (ec_key == NULL) {
        tloge("d2i ec pub failed");
        return -1;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        tloge("get ec group failed");
        goto clean;
    }

    ret = ecc_nid_boringssl2tom(EC_GROUP_get_curve_name(group));
    if (ret < 0) {
        tloge("get ec group failed");
        goto clean;
    }
    ecc_pub->domain = (uint32_t)ret;

    point = EC_KEY_get0_public_key(ec_key);
    if (point == NULL) {
        tloge("get ec group failed");
        goto clean;
    }

    ret = get_ecc_pub_from_cert_helper(ecc_pub, group, point);
clean:
    EC_KEY_free(ec_key);

    return ret;
}

int import_pub_from_sp(void *pub, const uint8_t *in, uint32_t inlen)
{
    int32_t ret;
    uint32_t keytype;

    if (pub == NULL || in == NULL) {
        tloge("invalid args");
        return -1;
    }

    ret = get_keytype_from_sp(in, inlen);
    if (ret < 0) {
        tloge("get key type failed");
        return -1;
    }

    keytype = (uint32_t)ret;
    switch (keytype) {
    case RSA_ALG:
        return get_rsa_pub_from_cert(pub, in, inlen);
    case ECC_ALG:
        return get_ecc_pub_from_cert(pub, in, inlen);
    default: /* Keytype not supported */
        tloge("invalid key type");
        return -1;
    }
}

static int public_get_subject_public_key(uint8_t *pub, uint32_t pub_size,
    bool check_size, const uint8_t *cert, uint32_t cert_len)
{
    X509 *cert_x509 = NULL;
    int len         = -1;
    EVP_PKEY *pkey  = NULL;

    if (pub == NULL || cert == NULL)
        return -1;

    cert_x509 = d2i_X509(NULL, (const unsigned char **)(&cert), cert_len);
    if (cert_x509 == NULL) {
        tloge("d2i x509 cert failed");
        goto clean;
    }

    pkey = X509_get_pubkey(cert_x509);
    if (pkey == NULL) {
        tloge("x509 get pubkey failed");
        goto clean;
    }

    if (check_size) {
        int pub_len;

        pub_len = i2d_PUBKEY(pkey, NULL);
        if ((uint32_t)pub_len > pub_size) {
            tloge("invalid pub size, %d", pub_len);
            goto clean;
        }
    }

    len = i2d_PUBKEY(pkey, &pub);

clean:
    EVP_PKEY_free(pkey);
    X509_free(cert_x509);

    return len;
}

int get_subject_public_key_new(uint8_t *pub, uint32_t pub_size, const uint8_t *cert, uint32_t cert_len)
{
    return public_get_subject_public_key(pub, pub_size, true, cert, cert_len);
}

/* this is not safe, but it's an export API */
int get_subject_public_key(uint8_t *pub, const uint8_t *cert, uint32_t cert_len)
{
    return public_get_subject_public_key(pub, 0, false, cert, cert_len);
}

int get_validity_from_cert(validity_period_t *vd, uint8_t *cert, uint32_t cert_len)
{
    X509 *cert_x509   = NULL;
    ASN1_STRING *time = NULL;
    int ret           = -1;

    if (vd == NULL || cert == NULL) {
        tloge("invalid args");
        return -1;
    }

    cert_x509 = d2i_X509(NULL, (const unsigned char **)(&cert), cert_len);
    if (cert_x509 == NULL) {
        tloge("d2i x509 cert failed");
        goto clean;
    }

    time = X509_get_notBefore(cert_x509);
    if (memcpy_s(vd->start, sizeof(vd->start), ASN1_STRING_data(time), ASN1_STRING_length(time))) {
        tloge("copy start time failed");
        goto clean;
    }

    time = X509_get_notAfter(cert_x509);
    if (memcpy_s(vd->end, sizeof(vd->end), ASN1_STRING_data(time), ASN1_STRING_length(time))) {
        tloge("copy end time failed");
        goto clean;
    }

    ret = 0;

clean:
    X509_free(cert_x509);

    return ret;
}

static int get_subject_by_name(uint8_t *buff, uint32_t len, const char *name, const uint8_t *cert, uint32_t cert_len)
{
    X509 *cert_x509       = NULL;
    X509_NAME *x_name     = NULL;
    ASN1_OBJECT *asn1_obj = NULL;
    int ret               = -1;

    if (buff == NULL || cert == NULL)
        return -1;

    cert_x509 = d2i_X509(NULL, (const unsigned char **)(&cert), cert_len);
    if (cert_x509 == NULL) {
        tloge("d2i x509 cert failed");
        goto clean;
    }

    x_name = X509_get_subject_name(cert_x509);
    if (x_name == NULL) {
        tloge("x509 get subject name failed");
        goto clean;
    }

    asn1_obj = OBJ_txt2obj(name, 0);
    if (asn1_obj == NULL) {
        tloge("c2i asn1 obj failed");
        goto clean;
    }

    ret = X509_NAME_get_text_by_OBJ(x_name, asn1_obj, (char *)buff, (int)len);
    if (ret < 0) {
        tloge("x509 get text by obj failed");
        goto clean;
    }

clean:
    ASN1_OBJECT_free(asn1_obj);
    X509_free(cert_x509);

    return ret;
}

int get_subject_x509_cn(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len)
{
    return get_subject_by_name(name, name_size, "CN", cert, cert_len);
}

int get_subject_CN(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len)
{
    return get_subject_x509_cn(name, name_size, cert, cert_len);
}

int get_subject_x509_ou(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len)
{
    return get_subject_by_name(name, name_size, "OU", cert, cert_len);
}

int get_subject_OU(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len)
{
    return get_subject_x509_ou(name, name_size, cert, cert_len);
}

int get_serial_number_from_cert(uint8_t *serial_number, uint32_t serial_number_size, uint8_t *cert, uint32_t cert_len)
{
    X509 *cert_x509           = NULL;
    ASN1_INTEGER *asn1_serial = NULL;
    int serial_len;
    int ret = -1;

    if (serial_number == NULL || cert == NULL)
        return -1;

    cert_x509 = d2i_X509(NULL, (const unsigned char **)(&cert), (long)cert_len);
    if (cert_x509 == NULL) {
        tloge("d2i x509 cert failed");
        goto clean;
    }

    asn1_serial = X509_get_serialNumber(cert_x509);
    if (asn1_serial == NULL) {
        tloge("get serial num failed");
        goto clean;
    }

    serial_len = i2d_ASN1_INTEGER(asn1_serial, NULL);
    if ((uint32_t)serial_len > serial_number_size) {
        tloge("serial buffer too small, %u/%d", serial_number_size, serial_len);
        goto clean;
    }

    ret = i2d_ASN1_INTEGER(asn1_serial, &serial_number);

clean:
    X509_free(cert_x509);

    return ret;
}

int get_issuer_from_cert(uint8_t *issuer, uint32_t issuer_size, uint8_t *crl, uint32_t crl_len)
{
    X509 *crl_x509    = NULL;
    X509_NAME *x_name = NULL;
    int ret           = -1;
    int issuer_len;

    if (issuer == NULL || crl == NULL)
        return -1;

    crl_x509 = d2i_X509(NULL, (const unsigned char **)(&crl), (long)crl_len);
    if (crl_x509 == NULL) {
        tloge("d2i x509 cert failed");
        goto clean;
    }

    x_name = X509_get_issuer_name(crl_x509);
    if (x_name == NULL) {
        tloge("get issuer failed");
        goto clean;
    }

    issuer_len = i2d_X509_NAME(x_name, NULL);
    if ((uint32_t)issuer_len > issuer_size) {
        tloge("crl len too small, %d/%u", issuer_len, issuer_size);
        goto clean;
    }

    ret = i2d_X509_NAME(x_name, &issuer);
clean:
    X509_free(crl_x509);

    return ret;
}
