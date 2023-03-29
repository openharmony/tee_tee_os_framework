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
#ifndef PERM_SRV_TA_CRL_H
#define PERM_SRV_TA_CRL_H

#include <dlist.h>
#include <tee_defines.h>
#include <crl_api.h>
#include <pthread.h>

#define CRL_CERT_LIST_MAX_SIZE 0x8000

#define TLV_TLEN       sizeof(uint8_t)
#define TLV_LLEN       sizeof(uint32_t)
#define TLV_HEADER_LEN (TLV_TLEN + TLV_LLEN)

struct revoked_node_t {
    struct dlist_node head;
    uint8_t sn[CERT_UNIVERSAL_LEN];
    uint32_t sn_size;
    uint8_t revoked_date[ASN1_FORMAT_TIME_SIZE];
};

struct crl_issuer_t {
    struct dlist_node head;
    uint8_t issuer[CERT_LARGE_LEN];
    uint32_t issuer_size;
    struct dlist_node revoked_node_list;
};

struct revoked_config_t {
    struct dlist_node crl_issuer_list;
    const char *list_file;
    uint16_t issuer_count;
    uint16_t revoked_count;
    pthread_mutex_t lock;
};

TEE_Result perm_srv_global_ta_crl_list_loading(bool check_empty);
TEE_Result perm_srv_check_cert_revoked(const uint8_t *sn, uint32_t sn_size, const uint8_t *issuer, uint32_t issuer_size,
                                       bool *revoked);
TEE_Result perm_srv_ta_crl_cert_process(const uint8_t *crl_cert, uint32_t crl_cert_size);
void perm_srv_print_buff(const uint8_t *buff, size_t buff_size);
#endif
