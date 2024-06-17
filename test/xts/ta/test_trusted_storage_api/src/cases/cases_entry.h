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
#ifndef CASE_HEADER_H_
#define CASE_HEADER_H_
#include "test_trusted_storage_api_defines.h"
#include "monad.h"

enum {
    CASE_PRESET_RESULT = -1,
    CASE_RAN_FLAG_SET = 1,
    CASE_RAN_FLAG_CLEAR = 0,
};

typedef struct {
    char name[MAX_STRING_NAME_LEN];
    int (*entry)(void);
    uint8_t ranFlag;
    int ret;
} CaseEntry;

// cases_trusted_storage.c
int CaseCreatePersistentObjectAndDelete(void);
int CaseRenameObjectAndGetInfo(void);
int CaseEnumerateDeleteAllObject(void);
int CaseRestrictObjectUsage(void);
int CasePopulateAndCopyObject(void);
int CaseGenerateKey(void);

// cases_entry.c
int RunCaseEntryById(uint32_t startId, uint32_t runCnt, uint32_t cf);
int RunCaseEntryByName(const char *name, uint32_t runCnt, uint32_t cf);
int GetRunCaseResult(uint32_t *runCnt, uint32_t *failCnt, uint32_t *passCnt);
#endif // CASE_HEADER_H_