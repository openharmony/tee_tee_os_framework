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
#ifndef _CRL_API_H
#define _CRL_API_H
#include <tee_defines.h>

#define TYPE_SEQUENCE           0x30
#define TYPE_BITSTRING          0x03
#define TYPE_UTCTIME            0x17
#define TYPE_INTEGER            0x02
#define TYPE_CONTEXT_SPECIFIC   0xA0
#define TYPE_TAG3               0x03

#define ASN1_FORMAT_TIME_SIZE   13
#define CERT_UNIVERSAL_LEN      64
#define CERT_LARGE_LEN          256
#define REVOKED_DATA_SIZE       13
#define REVOCATION_LIST_ELEM_ID 5
#define ISSUER_ELEM_ID          2
#define PATH_MAX                4096

typedef struct cert_list_entry_st {
    uint8_t serial[CERT_UNIVERSAL_LEN];
    uint32_t serial_size;
    uint8_t revoked_date[REVOKED_DATA_SIZE];
    struct cert_list_entry_st *next;
} cert_list_entry_t;

int32_t get_revocation_list_from_crl(const uint8_t *crl, uint32_t crl_len, cert_list_entry_t *entry);

int32_t get_issuer_from_crl(uint8_t *issuer, uint32_t issuer_size, const uint8_t *crl, uint32_t crl_len);

#endif /* _CRL_API_H */
