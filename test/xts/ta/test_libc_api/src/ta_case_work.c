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

#include "ta_case_work.h"
#include <tee_log.h>

void CaseRunner(CaseInfo *caseList, const uint32_t caseNum)
{
    for (uint32_t idx = 0; idx < caseNum; idx++) {
        CaseInfo *info = caseList + idx;
        tlogi("start case: %s ----- [%u/%u]", info->caseDesc, idx + 1, caseNum);
        info->ret = info->pfunc();
        if (info->ret != TEE_SUCCESS) {
            tloge("run case %s failed, ret: 0x%x", info->caseDesc, info->ret);
        } else {
            tlogi("run case %s passed !", info->caseDesc);
        }
    }
}

uint32_t CaseReporter(CaseInfo *caseList, const uint32_t caseNum)
{
    uint32_t failCount = 0;

    tlogi("Finished to run all %u cases, start to report:", caseNum);
    for (uint32_t idx = 0; idx < caseNum; idx++) {
        CaseInfo *info = caseList + idx;
        if (info->ret != TEE_SUCCESS) {
            failCount++;
            tloge("CASE %u --> %s [FAILED], ret: 0x%x", idx + 1, info->caseDesc, info->ret);
        }
    }

    if (failCount == 0) {
        tlogi("All %u Cases Passed !!!", caseNum);
    } else {
        tloge("[Case Failure] Total %u Cases Failed !!!", failCount);
    }

    return failCount;
}
