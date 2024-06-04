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
#ifndef __GMSSL_INTERNAL_H__
#define __GMSSL_INTERNAL_H__

#include <crypto_driver_adaptor.h>
#include <crypto/sm2.h>
#ifdef OPENSSL3_ENABLE
#include <internal/sm3.h>
#else
#include <crypto/sm3.h>
#endif
#ifndef OPENSSL_NO_SM4
#include <crypto/sm4.h>
#endif
#include <crypto/evp.h>
#include <openssl/evp.h>
#ifdef CRYPTO_SUPPORT_SOFT_ECC
#include <openssl/ec.h>
#include <ec/ec_local.h>
#endif
#include "crypto/ec.h"
#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/modes.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <bn/bn_local.h>
#include <tee_log.h>
#include <tee_crypto_api.h>

#define KEY_SIZE                 32
#define KEY_SIZE_2               64
#define HEX_LEN                  2
#define RAND_SIZE                64
#define SM4_BLOCK                16
#define MOD_LEN                  65 /* 256/8*2+1 */
#define ONLY_PUBLIC_LEN          3
#define KEYPAIR_LEN              4
#define GMSSL_OK                 1
#define GMSSL_ERR                0
#define STR_END_ZERO             1
#define HASH_SIZE                32
#define COORDINATE_LEN           32
#define COORDINATE_NUM           2
#define SM2_CIPHER_START         0x04
#define SM2_CIPHER_START_LEN     1
#define SIG_COMPONENT_SIZE       32
#define SIG_COMPONENT_NUM        2
#define SM2_CIPHER_INCREASE      97
#define BYTE_TO_BIT              8
#define SM2_INCREASE_MAX         110
#define STR_TO_HEX               2
#define HEX_FLAG                 16
#define SM2_GROUP_NOSTANDARD     0x12
#define SM2_ENCRYPTED_LEN        200
#define SM2_INCREASE_MIN         106
#define SM2_SIGN_MAX             72
#define SM2_SIGN_MIN             70
#define SM2_DIGEST_LEN           32
#define SM2_KEYPAIR_ATTR_COUNT   4
#define SM2_KEY_SIZE_BIT         256
#define SM2_SIG_LEN              64
#define SM2_MAX_PLAINTEXT_LENGTH 1024

#ifdef CRYPTO_SUPPORT_SOFT_SM2
struct sm2_public_key {
    uint8_t sm2_x[KEY_SIZE_2 + 1];
    uint8_t sm2_y[KEY_SIZE_2 + 1];
    uint32_t group;
};

struct sm2_public_key_2 {
    uint8_t sm2_x[KEY_SIZE];
    uint8_t sm2_y[KEY_SIZE];
    uint32_t group;
};

typedef struct sm2_key_pair_s {
    char x[KEY_SIZE_2];
    char y[KEY_SIZE_2];
    char d[KEY_SIZE_2];
} sm2_key_pair;

struct ec_key_pair_bignum_t {
    EC_GROUP *group;
    EC_POINT *point;
    BIGNUM *big_p;
    BIGNUM *big_a;
    BIGNUM *big_b;
    BIGNUM *big_d;
    BIGNUM *big_x;
    BIGNUM *big_y;
    BIGNUM *big_n;
    BIGNUM *big_h;
    BN_CTX *ctx;
};

struct sm2_eckey_get_dxy_t {
    char *d;
    char *x;
    char *y;
    int32_t d_len;
    int32_t x_len;
    int32_t y_len;
};

struct sm2_new_ec_group_t {
    const char *p_hex;
    const char *a_hex;
    const char *b_hex;
    const char *x_hex;
    const char *y_hex;
    const char *n_hex;
    const char *h_hex;
};

#endif
#endif
