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
#include "securec.h"
#include "tee_log.h"
#include "test_trusted_storage_api_defines.h"
#include "monad.h"

int MonadSetup2(TestVector *tv, IntermediateReprestation *ir)
{
    (void)ir;
    ir->tv = tv;
    ir->mrplSize = MONAD_REVERSE_PROP_LIST_SIZE;
    int ret = CopyReversElementList(ir->mrpl, &(ir->mrplSize));
    if (ret != 0) {
        tloge("[%s]:CopyReversElementList failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:MonadSetup2 success\n", __func__);
    return 0;
}

static int CheckExpResult2(int realRet, int tvExpRet, const char *info)
{
    if ((tvExpRet != 0) && realRet == 0) {
        tloge("[%s]:expect fail, but pass. tvExpRet[0x%x], realRet[0x%x]\n",
            info, tvExpRet, realRet);
            return -1;
    } else if ((tvExpRet == 0) && realRet != 0) {
        tloge("[%s]:expect pass, but fail. tvExpRet[0x%x], realRet[0x%x]\n",
            info, tvExpRet, realRet);
            return -1;
    } else if ((tvExpRet != 0) && realRet != 0) {
        tlogi("[%s]:expect fail, and fail. tvExpRet[0x%x], realRet[0x%x]\n",
            info, tvExpRet, realRet);
            return 0;
    } else if ((tvExpRet == 0) && realRet == 0) {
        tlogi("[%s]:expect pass, and pass. tvExpRet[0x%x], realRet[0x%x]\n",
            info, tvExpRet, realRet);
            return 0;
    }
    return 0;
}

int MonadTearDown(IntermediateReprestation *ir)
{
    int ret = BalanceGroupElementList(ir);
    if (ret != 0) {
        tloge("[%s]:BalanceGroupElementList failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:MonadTearDown success\n", __func__);
    return 0;
}

int MonadRun2(TestVector *tv)
{
    IntermediateReprestation ir;
    int ret = memset_s((void *)&ir, sizeof(IntermediateReprestation), 0, sizeof(IntermediateReprestation));
    if (ret != EOK) {
        tloge("[%s]:memset_s failed\n", __func__);
        return -1;
    }

    ret = MonadSetup2(tv, &ir);
    if (ret != 0) {
        tloge("[%s]:MonadSetup2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadSetup2 success\n", __func__);

    int checkResult;
    uint32_t i;
    for (i = 0; i < MAX_ACTIONS_SIZE; i++) {
        if (tv->actions[i] == NULL) {
            tlogi("[%s]:actions size is %u\n", __func__, i);
            break;
        }
        ret = tv->actions[i](&ir);
        if (ret != 0) {
            tloge("[%s]:%uth action excute failed, break pipeline.\n", __func__, i);
            break;
        }
    }
    checkResult = CheckExpResult2(ret, tv->expRet, __func__);
    if (checkResult != 0) {
        tloge("[%s]:CheckExpResult failed at %dth act in of seq.\n", __func__, i);
    }

    ret = MonadTearDown(&ir);
    if (ret != 0) {
        tloge("[%s]:MonadTearDown sucess\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadTearDown sucess\n", __func__);

    return checkResult;
}
