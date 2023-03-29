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
#include "crl_api.h"
#include <securec.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include "crypto_wrapper.h"

#define UPPER_BOUND   5
/*
 * Process SEQUENCES: signature, issuer, thisUpdate, nextUpdate, revokedCertificates and crlExtensions,
 * for TBS SEQUENCES are subject and subjectPublicKeyInfo
 */
static int32_t process_sequence_element(const uint8_t **elem, uint32_t elem_id, const uint8_t *tbs, uint32_t tbs_len)
{
    uint32_t i;
    uint32_t type;
    uint32_t hlen = 0;
    int32_t len = 0;
    bool check = false;

    for (i = 1; i <= UPPER_BOUND; i++) {
        check = ((len = get_next_tlv(&type, &hlen, tbs, tbs_len)) < 0 ||
            ((type != TYPE_SEQUENCE) && (type != TYPE_UTCTIME)));
        if (check)
            return -1;

        if (i == elem_id) {
            *elem = tbs;
            return len + (int32_t)hlen;
        }
        tbs_len -= ((uint32_t)len + hlen);
        tbs += ((uint32_t)len + hlen);
    }

    if (i == UPPER_BOUND + 1) {
        /* Only possibility is that we have extension */
        check = ((len = get_next_tlv(&type, &hlen, tbs, tbs_len)) < 0 ||
            type != (TYPE_CONTEXT_SPECIFIC | TYPE_TAG3));
        if (check)
            return -1;
        *elem = tbs;
        return len + (int32_t)hlen;
    }
    return -1;
}

static int32_t get_tbs_element_from_crl(const uint8_t **elem, uint32_t elem_id, const uint8_t *cert, uint32_t cert_len)
{
    const uint8_t *tbs   = NULL;
    uint32_t tbs_len;
    uint32_t type;
    uint32_t hlen        = 0;
    int32_t len          = 0;

    /* *elem may be null here */
    bool check = (elem == NULL || cert == NULL);
    if (check)
        return -1;
    type = 0;
    /* Go to tbs */
    check = ((len = get_next_tlv(&type, &hlen, cert, cert_len)) <= 0 || type != TYPE_SEQUENCE);
    if (check)
        return -1;
    tbs     = cert + hlen;
    tbs_len = cert_len - hlen;

    type = 0;
    /* Step into tbs */
    check = ((len = get_next_tlv(&type, &hlen, tbs, tbs_len)) <= 0 || type != TYPE_SEQUENCE);
    if (check)
        return -1;

    tbs += hlen;

    if (tbs_len < hlen)
        return -1;
    tbs_len -= hlen;

    type = 0;
    /* Skip version */
    check = ((len = get_next_tlv(&type, &hlen, tbs, tbs_len)) <= 0 ||
        ((type != TYPE_CONTEXT_SPECIFIC) && (type != TYPE_INTEGER)));
    if (check)
        return -1;
    if (elem_id == 0) {
        *elem = tbs + hlen;
        return len;
    }
    if (hlen > (tbs_len - (uint32_t)len) || (uint32_t)len + hlen < hlen)
        return -1;

    tbs_len -= ((uint32_t)len + hlen);
    tbs += ((uint32_t)len + hlen);

    return process_sequence_element(elem, elem_id, tbs, tbs_len);
}

static int32_t get_next_tlv_helper(uint32_t *header_len, const uint8_t *buf, uint32_t buf_len, uint32_t expected_type)
{
    uint32_t type = 0;
    int32_t len = 0;
    bool check = ((len = get_next_tlv(&type, header_len, buf, buf_len)) < 0 ||
        type != expected_type);
    if (check)
        return -1;

    return len;
}

/* Reads subject revocation list from the certificate
 * @param name           [out] points to revocation list
 * @param name_size       [in]  is the length of revocation list in bytes
 * @param cert           [in]  cert is buffer from where we are looking revocation list
 * @param cert_len        [in]  cert_len is length of certificate in bytes
 * @Return length of revocation list in bytes when found and otherwice -1.
 * * */
static int32_t crl_get_entry(const uint8_t *seq, uint32_t seq_len, cert_list_entry_t *entry)
{
    const uint8_t *crl_ptr        = NULL;
    cert_list_entry_t *curr_entry = entry;
    uint32_t hlen                 = 0;
    int32_t len                   = 0;

    bool check = (entry == NULL || seq == NULL);
    if (check)
        return -1;

    if (seq_len == 0)
        return 0;

    crl_ptr = seq;
    if ((len = get_next_tlv_helper(&hlen, crl_ptr, seq_len, TYPE_SEQUENCE)) < 0)
        return -1;
    crl_ptr += hlen;
    seq_len -= hlen;

    while (seq_len > 0) {
        const uint8_t *inner_ptr = crl_ptr;
        uint32_t inner_len       = seq_len;
        /* Process ans1 sequence tag */
        if ((len = get_next_tlv_helper(&hlen, inner_ptr, inner_len, TYPE_SEQUENCE)) < 0)
            return -1;
        crl_ptr += (hlen + (uint32_t)len);
        seq_len -= (hlen + (uint32_t)len);
        inner_ptr += hlen;
        inner_len -= hlen;

        /* Process serial number */
        if ((len = get_next_tlv_helper(&hlen, inner_ptr, inner_len, TYPE_INTEGER)) < 0)
            return -1;
        if (memcpy_s(curr_entry->serial, sizeof(curr_entry->serial), inner_ptr, len + hlen) != EOK)
            return -1;
        curr_entry->serial_size = (uint32_t)len + hlen;
        inner_ptr += (hlen + (uint32_t)len);
        inner_len -= (hlen + (uint32_t)len);

        /* Process revocation date */
        if ((len = get_next_tlv_helper(&hlen, inner_ptr, inner_len, TYPE_UTCTIME)) < 0)
            return -1;
        if (memcpy_s(curr_entry->revoked_date, sizeof(curr_entry->revoked_date), inner_ptr + hlen, len) != EOK)
            return -1;
        inner_ptr += (hlen + (uint32_t)len);
        inner_len -= (hlen + (uint32_t)len);

        if (inner_len > 0) {
            curr_entry->next = TEE_Malloc(sizeof(cert_list_entry_t), 0);
            if (curr_entry->next == NULL)
                return -1;
            curr_entry = curr_entry->next;
        }
    }

    return 0;
}

int32_t get_revocation_list_from_crl(const uint8_t *crl, uint32_t crl_len, cert_list_entry_t *entry)
{
    const uint8_t *crl_ptr = NULL;

    if (entry == NULL)
        return -1;
    if (crl == NULL)
        return -1;
    if ((int32_t)(crl_len = (uint32_t)get_tbs_element_from_crl(&crl_ptr, REVOCATION_LIST_ELEM_ID, crl, crl_len)) < 0)
        return -1;
    if (crl_get_entry(crl_ptr, crl_len, entry) < 0)
        return -1;

    return 0;
}

/* Reads last update time from the certificate
 * @param name           [out] points to last update time
 * @param name_size       [in]  is the length of last update time in bytes
 * @param cert           [in]  cert is buffer from where we are looking last update time
 * @param cert_len        [in]  cert_len is length of certificate in bytes
 * @Return length of last update time in bytes when found and otherwice -1.
 * * */
int32_t get_issuer_from_crl(uint8_t *issuer, uint32_t issuer_size, const uint8_t *crl, uint32_t crl_len)
{
    const uint8_t *pub_ptr = NULL;
    int32_t len            = -1;

    if (issuer == NULL)
        return -1;
    if (crl == NULL)
        return -1;
    if ((len = get_tbs_element_from_crl(&pub_ptr, ISSUER_ELEM_ID, crl, crl_len)) < 0)
        return -1;

    if ((uint32_t)len > issuer_size)
        return -1;

    if (memcpy_s(issuer, issuer_size, pub_ptr, len) != EOK)
        return -1;

    return len;
}
