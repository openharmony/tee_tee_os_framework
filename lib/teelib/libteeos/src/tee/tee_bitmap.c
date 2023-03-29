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

#include "tee_bitmap.h"

#define INVALID_BIT (-1)

int32_t get_valid_bit(const uint8_t *bitmap, uint32_t bit_max)
{
    uint32_t index1;
    uint32_t index2;
    int32_t  valid_bit = INVALID_BIT;

    if (bitmap == NULL)
        return valid_bit;

    for (index1 = 0; index1 < (bit_max >> MOVE_BIT); index1++) {
        if (bitmap[index1] == BITMAP_MASK)
            continue;
        for (index2 = 0; index2 < INDEX_MAX; index2++) {
            if (!(bitmap[index1] & (0x1U << index2))) {
                valid_bit = index1 * INDEX_MAX + index2;
                break;
            }
        }
        if (valid_bit != INVALID_BIT)
            break;
    }

    return valid_bit;
}
