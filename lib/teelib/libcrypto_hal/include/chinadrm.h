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
#ifndef CHINADRM_SRE_CHINADRM_H
#define CHINADRM_SRE_CHINADRM_H

#include <stdint.h>
#include <tee_defines.h>
struct cdrm_params {
    uint8_t *pkey;
    uint32_t pkey_len;
    uint8_t *iv;
    uint32_t iv_len;
    uint8_t *input_buffer;
    uint32_t input_len;
    uint8_t *output_buffer;
    uint32_t *output_len;
    void *context;
    uint32_t alg;
};

struct cdrm_trans_params {
    uint64_t pkey;
    uint64_t iv;
    uint64_t input_buffer;
    uint64_t output_buffer;
    uint64_t output_len;
    uint64_t context;
    uint32_t pkey_len;
    uint32_t iv_len;
    uint32_t input_len;
    uint32_t alg;
};

/*
 * Do aes key wrap operation.
 * @param params [IN/OUT] The cdrm_params structure contains key/iv/input/output info
 *
 * @return  TEE_SUCCESS: Do aes key wrap operation success
 * @return       others: Do aes key wrap operation failed
 */
TEE_Result aes_key_wrap(struct cdrm_params *params);

/*
 * Do aes key unwrap operation.
 *
 * @param params [IN/OUT] The cdrm_params structure contains key/iv/input/output info
 *
 * @return  TEE_SUCCESS: Do aes key unwrap operation success
 * @return       others: Do aes key unwrap operation failed
 */
TEE_Result aes_key_unwrap(struct cdrm_params *params);

#endif
