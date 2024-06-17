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
#include "tee_crypto_api.h"
#include "test_crypto_data.h"
#include "monad.h"
#include "securec.h"
#include "tee_log.h"

static MonadReversibilityProperty g_groupReverseList[] = {
    {
        .elementName = "IRSetUp",
        .element = IRSetUp,
        .inverseElementName = "IRTearDown",
        .inverseElement = IRTearDown,
        .isBalanced = 0,
    },
    {
        .elementName = "GlbAlloc",
        .element = GlbAlloc,
        .inverseElementName = "GlbFree",
        .inverseElement = GlbFree,
        .isBalanced = 0,
    },
};

static uint32_t g_groupReverseListSize = (uint32_t)(sizeof(g_groupReverseList) / sizeof(g_groupReverseList[0]));

int CopyReversElementList(MonadReversibilityProperty *dest, uint32_t *destSize)
{
    if (*destSize < g_groupReverseListSize) {
        tloge("[%s]:destSize = %u < g_groupReverseListSize = %u\n", __func__,
            *destSize, g_groupReverseListSize);
        return -1;
    }

    uint32_t i;
    for (i = 0; i < g_groupReverseListSize; i++) {
        dest[i].element = g_groupReverseList[i].element;
        dest[i].elementName = g_groupReverseList[i].elementName;
        dest[i].inverseElement = g_groupReverseList[i].inverseElement;
        dest[i].inverseElementName = g_groupReverseList[i].inverseElementName;
        dest[i].isBalanced = g_groupReverseList[i].isBalanced;
    }
    *destSize = g_groupReverseListSize;

    tlogi("[%s]:CopyReversElementList success\n", __func__);
    return 0;
}

int DisbalanceGroupElement(MonadReversibilityProperty *list, uint32_t listSize, ActionEntryType element)
{
    uint32_t i;
    MonadReversibilityProperty *find = NULL;
    for (i = 0; i < listSize; i++) {
        if (list[i].element == element) {
            find = &(list[i]);
            break;
        }
    }

    if (find == NULL) {
        tloge("[%s]:could not find inverse elment\n", __func__);
        return -1;
    }
    tlogi("[%s]:find element dual %s -> %s\n", __func__, find->elementName, find->inverseElementName);

    find->isBalanced = GRUPP_NOT_BALANCED;

    tlogi("[%s]:DisbalanceGroupElement success\n", __func__);
    return 0;
}

int BalanceGroupElement(MonadReversibilityProperty *list, uint32_t listSize, ActionEntryType inverseElement)
{
    uint32_t i;
    MonadReversibilityProperty *find = NULL;
    for (i = 0; i < listSize; i++) {
        if (list[i].inverseElement == inverseElement) {
            find = &(list[i]);
            break;
        }
    }
    if (find == NULL) {
        tloge("[%s]:could not find inverse elment\n", __func__);
        return -1;
    }
    tlogi("[%s]:find element dual %s -> %s\n", __func__, find->elementName, find->inverseElementName);

    find->isBalanced = GROUP_BALANCED;

    tlogi("[%s]:BalanceGroupElement success\n", __func__);
    return 0;
}

int BalanceGroupElementList(IntermediateReprestation *ir)
{
    MonadReversibilityProperty *list = ir->mrpl;
    uint32_t listSize = ir->mrplSize;

    uint32_t i;
    for (i = 0; i < listSize; i++) {
        if (list[i].isBalanced == GRUPP_NOT_BALANCED) {
            int ret = list[i].inverseElement(ir);
            if (ret != 0) {
                tloge("[%s]:inverse element %s (<- element %s) excute failed\n", __func__,
                    list[i].inverseElementName, list[i].elementName);
                    return -1;
            }
            tlogi("[%s]:inverse element %s (<- element %s) excute success\n", __func__,
                list[i].inverseElementName, list[i].elementName);
        } else {
            tlogi("[%s]:inverse element %s (<- element %s) is balanced, just return.\n", __func__,
                list[i].inverseElementName, list[i].elementName);
        }
    }

    tlogi("[%s]:BalanceGroupElementList success\n", __func__);
    return 0;
}