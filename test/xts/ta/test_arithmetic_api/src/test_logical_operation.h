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

#ifndef __TEST_LOGICAL_OPERATION_H__
#define __TEST_LOGICAL_OPERATION_H__

#include <tee_ext_api.h>

TEE_Result TestBigIntCmp();
TEE_Result TestBigIntCmpS32();
TEE_Result TestBigIntShiftRight();
TEE_Result TestBigIntGetBit();
TEE_Result TestBigIntGetBitCount();
TEE_Result TestBigIntSetBit();
TEE_Result TestBigIntAssign();
TEE_Result TestBigIntAbs();

#endif