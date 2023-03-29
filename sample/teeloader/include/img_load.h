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

#ifndef TEE_LOADER_IMG_LOAD_H
#define TEE_LOADER_IMG_LOAD_H

#include <stdint.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define KEY_INFO_MAX         8

struct asym_key_t {
    uint32_t key_magic;
    uint32_t key_offset;
    uint32_t key_size;
};

struct secure_img_header {
    uint32_t header_size;
    unsigned long long kernel_load_addr;
    uint32_t kernel_size;
    uint32_t task_num;
    uint32_t task_total_size;
    uint32_t got_size;
    unsigned long long image_load_addr;
    unsigned long long task_offset;
    unsigned long long kernel_offset;
    uint32_t sig_key_version;
    unsigned long long sig_offset;
    struct asym_key_t teeos_key_info[KEY_INFO_MAX];
} __attribute__((packed));

/*
 * part_name: teeos partition name
 * part_size: part_name buffer size
 * maybe have other arguments
 */
int32_t load_teeos(const char *part_name, uint32_t part_size, ...);

#endif
