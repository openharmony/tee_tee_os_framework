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
#include "crypto_wrapper.h"
#include "crypto_inner_interface.h"

int x509_crl_validate(uint8_t *cert, uint32_t cert_len, uint8_t *parent_key, uint32_t parent_key_len)
{
    (void)cert;
    (void)cert_len;
    (void)parent_key;
    (void)parent_key_len;
    tloge("mix system do not support x509 crl validate\n");
    return -1;
}

int x509_cert_validate(uint8_t *cert, uint32_t cert_len, uint8_t *parent_key, uint32_t parent_key_len)
{
    (void)cert;
    (void)cert_len;
    (void)parent_key;
    (void)parent_key_len;
    tloge("mix system do not support x509 cert validate\n");
    return -1;
}

int get_keytype_from_sp(const uint8_t *in, uint32_t inlen)
{
    (void)in;
    (void)inlen;
    tloge("mix system do not support get keytype from sp\n");
    return -1;
}

int import_pub_from_sp(void *pub, const uint8_t *in, uint32_t inlen)
{
    (void)pub;
    (void)in;
    (void)inlen;
    tloge("mix system do not support import pub from sp\n");
    return -1;
}

int32_t get_subject_public_key(uint8_t *pub, const uint8_t *cert, uint32_t cert_len)
{
    (void)pub;
    (void)cert;
    (void)cert_len;
    tloge("mix system do not support get subject public key\n");
    return -1;
}

int get_validity_from_cert(validity_period_t *vd, uint8_t *cert, uint32_t cert_len)
{
    (void)vd;
    (void)cert;
    (void)cert_len;
    tloge("mix system do not support get validity from cert\n");
    return -1;
}

int32_t get_subject_CN(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len)
{
    (void)name;
    (void)name_size;
    (void)cert;
    (void)cert_len;
    tloge("mix system do not support get subject CN\n");
    return -1;
}

int32_t get_subject_x509_cn(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len)
{
    (void)name;
    (void)name_size;
    (void)cert;
    (void)cert_len;
    tloge("mix system do not support get subject CN\n");
    return -1;
}

int32_t get_subject_OU(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len)
{
    (void)name;
    (void)name_size;
    (void)cert;
    (void)cert_len;
    tloge("mix system do not support get subject OU\n");
    return -1;
}

int32_t get_subject_x509_ou(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len)
{
    (void)name;
    (void)name_size;
    (void)cert;
    (void)cert_len;
    tloge("mix system do not support get subject OU\n");
    return -1;
}

int get_serial_number_from_cert(uint8_t *serial_number, uint32_t serial_number_size, uint8_t *cert, uint32_t cert_len)
{
    (void)serial_number;
    (void)serial_number_size;
    (void)cert;
    (void)cert_len;
    tloge("mix system do not support get serial number from cert\n");
    return -1;
}

int get_issuer_from_cert(uint8_t *issuer, uint32_t issuer_size, uint8_t *crl, uint32_t crl_len)
{
    (void)issuer;
    (void)issuer_size;
    (void)crl;
    (void)crl_len;
    tloge("mix system do not support get issuer from cert\n");
    return -1;
}

int32_t get_subject_public_key_new(uint8_t *pub, uint32_t pub_size, const uint8_t *cert, uint32_t cert_len)
{
    (void)pub;
    (void)pub_size;
    (void)cert;
    (void)cert_len;
    tloge("mix system do not support get subject public key new\n");
    return -1;
}
