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
#include "io_operations.h"
#include "register_ops.h"
#include <stddef.h>

#define ALIGN_SIZE        8
#define IS_ALIGNED(x, a)  (((x) & ((typeof(x))(a) - 1)) == 0)

void read_from_io(void *to, const volatile void *from, unsigned long count)
{
    if (to == NULL || from == NULL)
        return;
    while (count && !IS_ALIGNED((uintptr_t)from, 8)) {
        *(uint8_t *)to = u8_read(from);
        from++;
        to++;
        count--;
    }

    while (count >= ALIGN_SIZE) {
        *(uint64_t *)to = u64_read(from);
        from += ALIGN_SIZE;
        to += ALIGN_SIZE;
        count -= ALIGN_SIZE;
    }

    while (count) {
        *(uint8_t *)to = u8_read(from);
        from++;
        to++;
        count--;
    }
}

void write_to_io(volatile void *to, const void *from, unsigned long count)
{
    if (to == NULL || from == NULL)
        return;
    while (count && !IS_ALIGNED((uintptr_t)to, 8)) {
        u8_write(*(uint8_t *)from, to);
        from++;
        to++;
        count--;
    }

    while (count >= ALIGN_SIZE) {
        u64_write(*(uint64_t *)from, to);
        from += ALIGN_SIZE;
        to += ALIGN_SIZE;
        count -= ALIGN_SIZE;
    }

    while (count) {
        u8_write(*(uint8_t *)from, to);
        from++;
        to++;
        count--;
    }
}
