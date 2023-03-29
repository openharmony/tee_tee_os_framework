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
#ifndef KUNPENG_DRV_SECUREBOOT_H
#define KUNPENG_DRV_SECUREBOOT_H

#include "tee_driver_module.h"
#define OEMKEY_MAGIC_NUM        0x55AA55AA
#define RES_NUM                 52
#define OEMKEY_SIZE             16
#define SHARED_MEM_OEMKEY       "oemkey"

#define DATA_SIZE_MAX           512

int32_t get_oemkey_info(unsigned long args, uint32_t args_len);

struct tee_oemkey_info {
    uint32_t  head_magic;   /* magic number: 4 */
    uint8_t   provision_key[OEMKEY_SIZE]; /* provision key: 1*16 */
    uint8_t   reserved[RES_NUM]; /* reserved bytes 52 */
    uint32_t  tail_magic; /* magic number: 4 */
} __attribute__((__packed__));

#endif
