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

#ifndef WB_AES_DECRYPT_H
#define WB_AES_DECRYPT_H

/* stub for white box in OH */
struct wb_tool_inter_key {
    const unsigned char *iv;
    const unsigned int *table2;
    unsigned char round_num;
};

static inline int wb_aes_decrypt_cbc(const struct wb_tool_inter_key *tool_key,
    const unsigned char *input, unsigned int in_len, unsigned char *output, unsigned int *out_len)
{
    (void)tool_key;
    (void)input;
    (void)in_len;
    (void)output;
    (void)out_len;

    tloge("white box not support\n");
    return -1;
}
#endif /* WB_AES_DECRYPT_H */
