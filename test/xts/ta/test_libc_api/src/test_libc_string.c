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

TEE_Result TestLibcString(void)
{
    static CaseInfo libcStringList[] = {
        CASE_REGISTOR(do_test_memcmp),
        CASE_REGISTOR(do_test_strcmp),
        CASE_REGISTOR(do_test_strchr),
        CASE_REGISTOR(do_test_strlen),
        CASE_REGISTOR(do_test_memset),
        CASE_REGISTOR(do_test_memmove),
        CASE_REGISTOR(do_test_memcpy),
        CASE_REGISTOR(do_test_wmemchr),
        CASE_REGISTOR(do_test_wcslen),
    };

    CaseRunner(libcStringList, number_of(libcStringList));
    return CaseReporter(libcStringList, number_of(libcStringList));
}