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

#ifndef TEST_CRYPTO_DATA_H
#define TEST_CRYPTO_DATA_H
#include "stddef.h"
#include "test_crypto_api_types.h"
// alg_map_data.c
AlgMapInfo *FindAlgMapInfo(char *algName);
KeyTypeMapInfo *FindKeyTypeValue(char *keyTypeName);

// key_object_database.c
int GetOrGenIRTestKeys(IntermediateReprestation *ir);
#endif // end TEST_CRYPTO_DATA_H