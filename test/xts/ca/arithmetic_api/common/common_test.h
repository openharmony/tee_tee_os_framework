/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __COMMON_TEST_H__
#define __COMMON_TEST_H__

#include <stdint.h>
#include <tee_client_type.h>

#define ARITHMETIC_API_UUID                                \
    {                                                      \
        0x9ac09588, 0xfed1, 0x4b1e,                        \
        {                                                  \
            0xbb, 0x36, 0xd3, 0xe5, 0xa3, 0xf2, 0x6c, 0x39 \
        }                                                  \
    }

enum TEST_ARITHMETIC_API_CMD_ID {
    CMD_ID_TEST_BIG_INT_COMPUTE_FMM = 0,
    CMD_ID_TEST_BIG_INT_INIT_FMM_CONTEXT = 1,
    CMD_ID_TEST_CONVERTER_BETWEEN_BIG_INT_AND_FMM = 2,
    CMD_ID_TEST_BIG_INT_EXP_MOD = 3,
    CMD_ID_TEST_CONVERTER_BETWEEN_BIG_INT_AND_OCTET_STRING = 4,
    CMD_ID_TEST_CONVERTER_BETWEEN_BIG_INT_AND_S32 = 5,
    CMD_ID_TEST_BIG_INT_ADD_AND_SUB_MOD = 6,
    CMD_ID_TEST_BIG_INT_MUL_AND_INV_MOD = 7,
    CMD_ID_TEST_BIG_INT_MOD = 8,
    CMD_ID_TEST_BIG_INT_ADD_AND_SUB = 9,
    CMD_ID_TEST_BIG_INT_NEG = 10,
    CMD_ID_TEST_BIG_INT_MUL_AND_SQUARE = 11,
    CMD_ID_TEST_BIG_INT_DIV = 12,
    CMD_ID_TEST_BIG_INT_SHIFT_RIGHT = 13,
    CMD_ID_TEST_BIG_INT_GET_BIT = 14,
    CMD_ID_TEST_BIG_INT_GET_BIT_COUNT = 15,
    CMD_ID_TEST_BIG_INT_SET_BIT = 16,
    CMD_ID_TEST_BIG_INT_ASSIGN = 17,
    CMD_ID_TEST_BIG_INT_ABS = 18,
    CMD_ID_TEST_BIG_INT_RELATIVE_PRIME = 19,
    CMD_ID_TEST_BIG_INT_COMPUTE_EXTENTED_GCD = 20,
    CMD_ID_TEST_BIG_INT_IS_PROBABLE_PRIME = 21,
    CMD_ID_TEST_BIG_INT_CMP = 22,
    CMD_ID_TEST_BIG_INT_CMP_S32 = 23,
    CMD_ID_TEST_BIG_INT_INIT_FMM = 24,
    CMD_ID_TEST_BIG_INT_INIT = 25,
};

#endif
