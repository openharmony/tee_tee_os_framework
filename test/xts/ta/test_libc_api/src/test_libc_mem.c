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

#include <test_libc_func.h>
#include "ta_case_work.h"

TEE_Result TestApplyAndFreeMem(void)
{
    static CaseInfo applyAndFreeMemList[] = {
        CASE_REGISTOR(do_test_calloc),
        CASE_REGISTOR(do_test_malloc),
        CASE_REGISTOR(do_test_free),
        CASE_REGISTOR(do_test_free_1),
    };

    CaseRunner(applyAndFreeMemList, number_of(applyAndFreeMemList));
    return CaseReporter(applyAndFreeMemList, number_of(applyAndFreeMemList));
}

TEE_Result TestMmapAndMunmap(void)
{
    static CaseInfo mmapAndMunmapList[] = {
        CASE_REGISTOR(test_mmap),
    };

    CaseRunner(mmapAndMunmapList, number_of(mmapAndMunmapList));
    return CaseReporter(mmapAndMunmapList, number_of(mmapAndMunmapList));
}