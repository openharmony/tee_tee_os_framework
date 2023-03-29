/*
 * Copyright (C) 2023 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef _TA_CASE_DEFINE_H_
#define _TA_CASE_DEFINE_H_

#include <tee_core_api.h>

#define number_of(x) (sizeof(x) / sizeof(x[0]))

typedef int (*CaseEntry)(void);

typedef struct {
    CaseEntry pfunc;
    char *caseDesc;
    TEE_Result ret;
} CaseInfo;

#define CASE_REGISTOR(func) {func, #func, 0}

void CaseRunner(CaseInfo *caseList, const uint32_t caseNum);
uint32_t CaseReporter(CaseInfo *caseList, const uint32_t caseNum);

#endif

