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
#include "tee_elf_verify_openssl.h"

TEE_Result tee_secure_img_decrypt_cipher_layer(const uint8_t *cipher_layer,
        uint32_t cipher_size, uint8_t *plaintext_layer, uint32_t *plaintext_size)
{
    (void)cipher_layer;
    (void)cipher_size;
    (void)plaintext_layer;
    (void)plaintext_size;
    return TEE_ERROR_NOT_SUPPORTED;
}
