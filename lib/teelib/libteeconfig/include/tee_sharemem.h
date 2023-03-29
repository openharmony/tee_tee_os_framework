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
#ifndef TEE_SHAREMEM_H
#define TEE_SHAREMEM_H

#include <stdint.h>

#define MAX_TAG_LEN 32
#define CHIP_TYPE_LEN_MAX 32

/*
 * when clear_flag is true, sharedmem buffer will be memset to zero
 * after sharedmem acquired firstly
 */
int32_t get_tlv_sharedmem(const char *type, uint32_t type_size,
                          void *buffer, uint32_t *size, bool clear_flag);
int32_t tee_get_chip_type(char *buffer, uint32_t buffer_len);

int32_t tee_shared_mem(const char *type, uint32_t type_size, void *buffer, uint32_t *buffer_size, bool clear_flag);
int32_t tee_get_oemkey_info(uint8_t *oem_key, size_t key_size);
#endif
