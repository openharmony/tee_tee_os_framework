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
#ifndef GTASK_TA_LOAD_KEY_H
#define GTASK_TA_LOAD_KEY_H

#include <tee_defines.h>
#include "ta_verify_key.h"

#define TAG_LEN 10
enum wb_tool_ver {
    WB_TOOL_KEY_128 = 1, /* white box root key's len is 128 bits */
    WB_TOOL_KEY_256, /* white box root key's len is 256 bits */
};

struct wb_tool_key {
    enum wb_tool_ver tool_ver;
    const uint8_t *iv;
    const uint32_t *table2;
    uint32_t round_num;
};

enum ta_type {
    V1_TYPE = 1,
    V2_TYPE, /* v2 ta's rsa key len is 2048bits */
    V3_TYPE_2048, /* v3 ta's encrypt rsa key len is 2048bits */
    V3_TYPE_3072, /* v3 ta's encrypt rsa key len is 3072bits */
};

enum protect_type {
    WB_KEY = 1,
    ECIES_KEY,
};

struct key_size_tag_info {
    char key_len_tag[TAG_LEN];
    enum verify_key_len key_len;
};

struct key_style_tag_info {
    char key_style_tag[TAG_LEN];
    enum verify_key_style key_style;
};

#define WB_2048_PRIV_LEN        144
#define WB_3072_PRIV_LEN        208
#define WB_PRIV_LEN             WB_3072_PRIV_LEN

#define BYTE_LEN                8
#define PADDING_LEN             16
#define BASE_LEN                2

#define WRAPPED_2048_PRIV_LEN   144
#define WRAPPED_2048_PUB_LEN_D  272
#define WRAPPED_3072_PRIV_LEN   208
#define WRAPPED_3072_PUB_LEN_D  400

#define WRAPPED_PRIV_LEN        WRAPPED_3072_PRIV_LEN
#define WRAPPED_PUB_LEN_D       WRAPPED_3072_PUB_LEN_D

struct wb_key_struct {
    unsigned char wb_rsa_priv_p[WB_PRIV_LEN];
    uint32_t wb_rsa_priv_p_len;
    unsigned char wb_rsa_priv_q[WB_PRIV_LEN];
    uint32_t wb_rsa_priv_q_len;
    unsigned char wb_rsa_priv_dp[WB_PRIV_LEN];
    uint32_t wb_rsa_priv_dp_len;
    unsigned char wb_rsa_priv_dq[WB_PRIV_LEN];
    uint32_t wb_rsa_priv_dq_len;
    unsigned char wb_rsa_priv_qinv[WB_PRIV_LEN];
    uint32_t wb_rsa_priv_qinv_len;
};

#define ECC_PUB_SIZE      65
#define IV_LEN            16
#define WRAPPED_PUB_LEN_E 16

struct ecies_key_struct {
    unsigned char ecc_pub[ECC_PUB_SIZE];
    unsigned char iv[IV_LEN];
    unsigned char wrapped_rsa_priv_p[WRAPPED_PRIV_LEN];
    uint32_t wrapped_rsa_priv_p_len;
    unsigned char wrapped_rsa_priv_q[WRAPPED_PRIV_LEN];
    uint32_t wrapped_rsa_priv_q_len;
    unsigned char wrapped_rsa_priv_dq[WRAPPED_PRIV_LEN];
    uint32_t wrapped_rsa_priv_dq_len;
    unsigned char wrapped_rsa_priv_dp[WRAPPED_PRIV_LEN];
    uint32_t wrapped_rsa_priv_dp_len;
    unsigned char wrapped_rsa_priv_qinv[WRAPPED_PRIV_LEN];
    uint32_t wrapped_rsa_priv_qinv_len;
    unsigned char wrapped_rsa_pub_d[WRAPPED_PUB_LEN_D];
    uint32_t wrapped_rsa_pub_d_len;
    unsigned char wrapped_rsa_pub_e[WRAPPED_PUB_LEN_E];
};

struct key_data {
    enum protect_type pro_type;
    enum ta_type ta_type;
    uint8_t *key;
    size_t key_len;
};

struct key_protype_tag_info {
    char key_type_str[TAG_LEN];
    enum protect_type pro_type;
};

struct key_type_tag_info {
    char key_type_str[TAG_LEN];
    enum ta_type ta_type;
};

bool is_wb_protecd_ta_key(void);
TEE_Result get_ta_load_key(struct key_data *key);
TEE_Result query_ta_verify_pubkey(const struct ta_verify_key *all_key, size_t all_key_num,
    struct ta_verify_key *query_key);
#endif
