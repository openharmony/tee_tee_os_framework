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
#include <securec.h>
#include <tee_log.h>
#include "crypto_inner_interface.h"

int ec_nid_tom2boringssl(uint32_t domain)
{
    (void)domain;
    return -1;
}

TEE_Result ecc_privkey_tee_to_boring(void *priv, void **eckey)
{
    (void)priv;
    (void)eckey;
    return TEE_ERROR_NOT_SUPPORTED;
}

int ecc_derive_public_key(ecc_priv_key_t *priv_info, ecc_pub_key_t *pub_info)
{
    (void)priv_info;
    (void)pub_info;
    return -1;
}

int derive_ecc_private_key_from_huk(ecc_priv_key_t *priv, const uint8_t *secret, uint32_t sec_len)
{
    (void)priv;
    (void)secret;
    (void)sec_len;
    return -1;
}

int derive_private_key_from_secret(void *priv, uint8_t *secret, uint32_t secret_len, uint32_t bits, uint32_t key_type,
                                   uint8_t *file_name)
{
    (void)priv;
    (void)secret;
    (void)secret_len;
    (void)bits;
    (void)key_type;
    (void)file_name;
    return -1;
}

int32_t ecc_export_pub(uint8_t *out, uint32_t out_size, ecc_pub_key_t *pub)
{
    (void)out;
    (void)out_size;
    (void)pub;
    return -1;
}

int32_t ecc_import_pub(ecc_pub_key_t *pub, const uint8_t *in, uint32_t inlen)
{
    (void)pub;
    (void)in;
    (void)inlen;
    return -1;
}

int32_t ecc_import_priv(ecc_priv_key_t *priv, const uint8_t *in, uint32_t inlen)
{
    (void)priv;
    (void)in;
    (void)inlen;
    return -1;
}

int32_t get_next_tlv(uint32_t *type, uint32_t *header_len, const uint8_t *buf, uint32_t buf_len)
{
    (void)type;
    (void)header_len;
    (void)buf;
    (void)buf_len;
    return -1;
}

int32_t ecc_sign_digest(uint8_t *signature, uint32_t sig_size, uint8_t *in, uint32_t in_len, ecc_priv_key_t *priv)
{
    (void)signature;
    (void)sig_size;
    (void)in;
    (void)in_len;
    (void)priv;
    return -1;
}

int32_t ecc_verify_digest(const uint8_t *signature, uint32_t sig_len, uint8_t *in, uint32_t in_len, ecc_pub_key_t *pub)
{
    (void)signature;
    (void)sig_len;
    (void)in;
    (void)in_len;
    (void)pub;
    return -1;
}
