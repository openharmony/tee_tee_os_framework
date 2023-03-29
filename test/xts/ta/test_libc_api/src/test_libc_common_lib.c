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

TEE_Result TestLibcMath(void)
{
    static CaseInfo libcMathList[] = {
        CASE_REGISTOR(do_test_atan),
        CASE_REGISTOR(do_test_ceil),
        CASE_REGISTOR(do_test_ceilf),
        CASE_REGISTOR(do_test_exp),
        CASE_REGISTOR(do_test_fabs),
        CASE_REGISTOR(do_test_floor),
        CASE_REGISTOR(do_test_frexpl),
        CASE_REGISTOR(do_test_log),
        CASE_REGISTOR(do_test_log2),
        CASE_REGISTOR(do_test_pow),
        CASE_REGISTOR(do_test_roundf),
        CASE_REGISTOR(do_test_sqrt),
    };

    CaseRunner(libcMathList, number_of(libcMathList));
    return CaseReporter(libcMathList, number_of(libcMathList));
}

TEE_Result TestLibcStdlib(void)
{
    static CaseInfo libcStdlibList[] = {
        CASE_REGISTOR(do_test_stdlib),
        CASE_REGISTOR(do_test_strtol),
        CASE_REGISTOR(do_test_getenv),
    };

    CaseRunner(libcStdlibList, number_of(libcStdlibList));
    return CaseReporter(libcStdlibList, number_of(libcStdlibList));
}

TEE_Result TestLibcCtype(void)
{
    static CaseInfo libcCtypeList[] = {
        CASE_REGISTOR(do_test_ctype),
        CASE_REGISTOR(do_test_wctype),
        CASE_REGISTOR(do_test_towfun),
    };

    CaseRunner(libcCtypeList, number_of(libcCtypeList));
    return CaseReporter(libcCtypeList, number_of(libcCtypeList));
}

TEE_Result TestLibcTime(void)
{
    static CaseInfo libcTimeList[] = {
        CASE_REGISTOR(do_test_clock_gettime),
        CASE_REGISTOR(do_test_strftime),
    };

    CaseRunner(libcTimeList, number_of(libcTimeList));
    return CaseReporter(libcTimeList, number_of(libcTimeList));
}

TEE_Result TestLibcStdio(void)
{
    static CaseInfo libcTimeList[] = {
        CASE_REGISTOR(do_test_vsprintf),
        CASE_REGISTOR(do_test_sprintf),
        CASE_REGISTOR(do_test_fflush),
        CASE_REGISTOR(do_test_stdio),
    };

    CaseRunner(libcTimeList, number_of(libcTimeList));
    return CaseReporter(libcTimeList, number_of(libcTimeList));
}

TEE_Result TestLibcError(void)
{
    static CaseInfo libcErrorList[] = {
        CASE_REGISTOR(test_error),
    };

    CaseRunner(libcErrorList, number_of(libcErrorList));
    return CaseReporter(libcErrorList, number_of(libcErrorList));
}

TEE_Result TestLibcUnistd(void)
{
    static CaseInfo libcUnistdList[] = {
        CASE_REGISTOR(do_test_getpid),
    };

    CaseRunner(libcUnistdList, number_of(libcUnistdList));
    return CaseReporter(libcUnistdList, number_of(libcUnistdList));
}

TEE_Result TestLibcLocale(void)
{
    static CaseInfo libcLocaleList[] = {
        CASE_REGISTOR(do_test_strtod1),
        CASE_REGISTOR(do_test_strtod2),
        CASE_REGISTOR(do_test_strtod3),
        CASE_REGISTOR(do_test_strcoll),
        CASE_REGISTOR(test_strxfrm),
    };

    CaseRunner(libcLocaleList, number_of(libcLocaleList));
    return CaseReporter(libcLocaleList, number_of(libcLocaleList));
}

TEE_Result TestLibcMultiByte(void)
{
    static CaseInfo libcMultiByteList[] = {
        CASE_REGISTOR(do_test_mbrtowc),
        CASE_REGISTOR(do_test_wcrtomb),
        CASE_REGISTOR(do_test_wctob),
    };

    CaseRunner(libcMultiByteList, number_of(libcMultiByteList));
    return CaseReporter(libcMultiByteList, number_of(libcMultiByteList));
}

TEE_Result TestLibcPrng(void)
{
    static CaseInfo libcPrngList[] = {
        CASE_REGISTOR(do_test_random),
        CASE_REGISTOR(do_test_srandom),
        CASE_REGISTOR(do_test_wctob),
    };

    CaseRunner(libcPrngList, number_of(libcPrngList));
    return CaseReporter(libcPrngList, number_of(libcPrngList));
}