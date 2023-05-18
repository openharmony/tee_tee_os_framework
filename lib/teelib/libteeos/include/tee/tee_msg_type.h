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

#ifndef __TEE_MSG_TYPE_H_
#define __TEE_MSG_TYPE_H_
#include <stdint.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)    (sizeof(a) / sizeof ((a)[0]))
#endif
typedef union {
    struct {
        uint8_t        msg_class;
        uint8_t        msg_flags;
        uint16_t    msg_id;
        uint32_t    msg_size;
    } __attribute__((packed)) send;

    struct {
        int64_t        ret_val;
        uint32_t    msg_size;
        uint32_t    reserve;
    } __attribute__((packed)) reply;
} msg_header;

#endif