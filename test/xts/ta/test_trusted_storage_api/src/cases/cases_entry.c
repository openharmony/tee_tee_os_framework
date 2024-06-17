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

#include "string.h"
#include "monad.h"
#include "cases_entry.h"

static CaseEntry g_caseEntryList[] = {
    {
        .name = "CaseCreatePersistentObjectAndDelete",
        .entry = CaseCreatePersistentObjectAndDelete,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseRenameObjectAndGetInfo",
        .entry = CaseRenameObjectAndGetInfo,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseEnumerateDeleteAllObject",
        .entry = CaseEnumerateDeleteAllObject,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseRestrictObjectUsage",
        .entry = CaseRestrictObjectUsage,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CasePopulateAndCopyObject",
        .entry = CasePopulateAndCopyObject,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseGenerateKey",
        .entry = CaseGenerateKey,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
};

static uint32_t g_caseEntryListSize = (uint32_t)(sizeof(g_caseEntryList) / sizeof(g_caseEntryList[0]));

static int FindCaseIdByName(const char *name, uint32_t *caseId)
{
    uint32_t i;
    for (i = 0; i < g_caseEntryListSize; i++) {
        if (strcmp((const char *)name, (const char *)(g_caseEntryList[i].name)) == 0) {
            *caseId = i;
            return 0;
        }
    }
    return -1;
}

int RunCaseEntryById(uint32_t startId, uint32_t runCnt, uint32_t cf)
{
    if (startId >= g_caseEntryListSize) {
        tloge("[%s]:invalid startId[%u]\n", __func__, startId);
        return -1;
    }
    uint32_t i;
    uint32_t runId;
    for (i = 0; i < runCnt && i + startId < g_caseEntryListSize; i++) {
        runId = i + startId;
        g_caseEntryList[runId].ranFlag = CASE_RAN_FLAG_SET;
        g_caseEntryList[runId].ret = g_caseEntryList[runId].entry();
        if (g_caseEntryList[runId].ret != 0) {
            tloge("[%s]:run case [%s] failed\n", __func__, g_caseEntryList[runId].name);
            if (cf == 0) {
                return -1;
            }
        } else {
            tlogi("[%s]:run case [%s] success\n", __func__, g_caseEntryList[runId].name);
        }
    }
    return 0;
}

int RunCaseEntryByName(const char *name, uint32_t runCnt, uint32_t cf)
{
    uint32_t startId;
    int ret = FindCaseIdByName(name, &startId);
    if (ret != 0) {
        tloge("[%s]:find case id by name [%s] failed\n", __func__, name);
        return -1;
    }
    return RunCaseEntryById(startId, runCnt, cf);
}

int GetRunCaseResult(uint32_t *runCnt, uint32_t *failCnt, uint32_t *passCnt)
{
    *runCnt = 0;
    *failCnt = 0;
    *passCnt = 0;
    uint32_t i;
    tlogi("[%s]:------------------------------------------\n", __func__);
    for (i = 0; i < g_caseEntryListSize; i++) {
        if (g_caseEntryList[i].ranFlag != CASE_RAN_FLAG_SET) {
            continue;
        }
        (*runCnt)++;
        char *rets = NULL;
        if (g_caseEntryList[i].ret == 0) {
            (*passCnt)++;
            rets = "pass";
        } else {
            (*failCnt)++;
            rets = "fail";
        }
        tlogi("[    %6s]:%s %s\n", rets, g_caseEntryList[i].name, rets);
    }
    tlogi("[  Report  ]:run %u cases, pass %u, fail %u\n", *runCnt, *passCnt, *failCnt);
    return (*failCnt == 0 && *passCnt != 0) ? 0 : -1;
}