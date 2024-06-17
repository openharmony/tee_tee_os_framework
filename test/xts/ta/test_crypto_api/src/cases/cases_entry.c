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
    // cases_export_plaintext_key.c
    {
        .name = "CaseSymEncryptAesEcbNopadKeySize128OnceOnce",
        .entry = CaseSymEncryptAesEcbNopadKeySize128OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesEcbNopadKeySize128OnceMulti",
        .entry = CaseSymEncryptAesEcbNopadKeySize128OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesEcbNopadKeySize128MultiOnce",
        .entry = CaseSymEncryptAesEcbNopadKeySize128MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesEcbNopadKeySize128MultiMulti",
        .entry = CaseSymEncryptAesEcbNopadKeySize128MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCbcNopadKeySize192OnceOnce",
        .entry = CaseSymEncryptAesCbcNopadKeySize192OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCbcNopadKeySize192OnceMulti",
        .entry = CaseSymEncryptAesCbcNopadKeySize192OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCbcNopadKeySize192MultiOnce",
        .entry = CaseSymEncryptAesCbcNopadKeySize192MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCbcNopadKeySize192MultiMulti",
        .entry = CaseSymEncryptAesCbcNopadKeySize192MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCtrKeySize128OnceOnce",
        .entry = CaseSymEncryptAesCtrKeySize128OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCtrKeySize128OnceMulti",
        .entry = CaseSymEncryptAesCtrKeySize128OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCtrKeySize128MultiOnce",
        .entry = CaseSymEncryptAesCtrKeySize128MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCtrKeySize128MultiMulti",
        .entry = CaseSymEncryptAesCtrKeySize128MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesXtsKeySize256OnceOnce",
        .entry = CaseSymEncryptAesXtsKeySize256OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesXtsKeySize256OnceMulti",
        .entry = CaseSymEncryptAesXtsKeySize256OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesXtsKeySize256MultiOnce",
        .entry = CaseSymEncryptAesXtsKeySize256MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesXtsKeySize256MultiMulti",
        .entry = CaseSymEncryptAesXtsKeySize256MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCbcPkcs5KeySize256OnceOnce",
        .entry = CaseSymEncryptAesCbcPkcs5KeySize256OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCbcPkcs5KeySize256OnceMulti",
        .entry = CaseSymEncryptAesCbcPkcs5KeySize256OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCbcPkcs5KeySize256MultiOnce",
        .entry = CaseSymEncryptAesCbcPkcs5KeySize256MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptAesCbcPkcs5KeySize256MultiMulti",
        .entry = CaseSymEncryptAesCbcPkcs5KeySize256MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CbcNopadKeySize128OnceOnce",
        .entry = CaseSymEncryptSm4CbcNopadKeySize128OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CbcNopadKeySize128OnceMulti",
        .entry = CaseSymEncryptSm4CbcNopadKeySize128OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CbcNopadKeySize128MultiOnce",
        .entry = CaseSymEncryptSm4CbcNopadKeySize128MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CbcNopadKeySize128MultiMulti",
        .entry = CaseSymEncryptSm4CbcNopadKeySize128MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CtrKeySize128OnceOnce",
        .entry = CaseSymEncryptSm4CtrKeySize128OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CtrKeySize128OnceMulti",
        .entry = CaseSymEncryptSm4CtrKeySize128OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CtrKeySize128MultiOnce",
        .entry = CaseSymEncryptSm4CtrKeySize128MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CtrKeySize128MultiMulti",
        .entry = CaseSymEncryptSm4CtrKeySize128MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4Cfb128KeySize128OnceOnce",
        .entry = CaseSymEncryptSm4Cfb128KeySize128OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4Cfb128KeySize128OnceMulti",
        .entry = CaseSymEncryptSm4Cfb128KeySize128OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4Cfb128KeySize128MultiOnce",
        .entry = CaseSymEncryptSm4Cfb128KeySize128MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4Cfb128KeySize128MultiMulti",
        .entry = CaseSymEncryptSm4Cfb128KeySize128MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CbcPkcs7KeySize128OnceOnce",
        .entry = CaseSymEncryptSm4CbcPkcs7KeySize128OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CbcPkcs7KeySize128OnceMulti",
        .entry = CaseSymEncryptSm4CbcPkcs7KeySize128OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CbcPkcs7KeySize128MultiOnce",
        .entry = CaseSymEncryptSm4CbcPkcs7KeySize128MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseSymEncryptSm4CbcPkcs7KeySize128MultiMulti",
        .entry = CaseSymEncryptSm4CbcPkcs7KeySize128MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    // cases_ae_crypto_basic_cases.c
    {
        .name = "CaseAEAesCcmK128N7T32Aad32MultiOnce",
        .entry = CaseAEAesCcmK128N7T32Aad32MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK128N7T32Aad32MultiMulti",
        .entry = CaseAEAesCcmK128N7T32Aad32MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK128N7T32Aad32update0Multi",
        .entry = CaseAEAesCcmK128N7T32Aad32update0Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK128N7T32Aad32OnceOnce",
        .entry = CaseAEAesCcmK128N7T32Aad32OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK128N7T32Aad32OnceMulti",
        .entry = CaseAEAesCcmK128N7T32Aad32OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK192N8T48Aad288MultiOnce",
        .entry = CaseAEAesCcmK192N8T48Aad288MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK192N8T48Aad288MultiMulti",
        .entry = CaseAEAesCcmK192N8T48Aad288MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK192N8T48Aad288OnceOnce",
        .entry = CaseAEAesCcmK192N8T48Aad288OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK192N8T48Aad288OnceMulti",
        .entry = CaseAEAesCcmK192N8T48Aad288OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK256N9T64Aad512MultiOnce",
        .entry = CaseAEAesCcmK256N9T64Aad512MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK256N9T64Aad512MultiMulti",
        .entry = CaseAEAesCcmK256N9T64Aad512MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK256N13T128Aad512OnceOnce",
        .entry = CaseAEAesCcmK256N13T128Aad512OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK256N13T128Aad512OnceMulti",
        .entry = CaseAEAesCcmK256N13T128Aad512OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK128N10T80Aad4MMultiOnce",
        .entry = CaseAEAesCcmK128N10T80Aad4MMultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK128N10T80Aad4MMultiMulti",
        .entry = CaseAEAesCcmK128N10T80Aad4MMultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK192N11T96Aad32MultiOnce",
        .entry = CaseAEAesCcmK192N11T96Aad32MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK192N11T96Aad32MultiMulti",
        .entry = CaseAEAesCcmK192N11T96Aad32MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK256N12T112Aad288MultiOnce",
        .entry = CaseAEAesCcmK256N12T112Aad288MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK256N12T112Aad288MultiMulti",
        .entry = CaseAEAesCcmK256N12T112Aad288MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK128N13T128Aad512MultiOnce",
        .entry = CaseAEAesCcmK128N13T128Aad512MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK128N13T128Aad512MultiMulti",
        .entry = CaseAEAesCcmK128N13T128Aad512MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK128N7T32Aad512EncryptOnlyTAG",
        .entry = CaseAEAesCcmK128N7T32Aad512EncryptOnlyTAG,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK192N8T64NoAadOnce",
        .entry = CaseAEAesCcmK192N8T64NoAadOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK192N8T64NoAadMulti",
        .entry = CaseAEAesCcmK192N8T64NoAadMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesCcmK256N9T64Aad512DecryptOnlyTAG",
        .entry = CaseAEAesCcmK256N9T64Aad512DecryptOnlyTAG,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK128N7T96Aad32MultiOnce",
        .entry = CaseAEAesGcmK128N7T96Aad32MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK128N7T96Aad32MultiMulti",
        .entry = CaseAEAesGcmK128N7T96Aad32MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK128N7T96Aad32update0Multi",
        .entry = CaseAEAesGcmK128N7T96Aad32update0Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK128N7T96Aad32OnceOnce",
        .entry = CaseAEAesGcmK128N7T96Aad32OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK128N7T96Aad32OnceMulti",
        .entry = CaseAEAesGcmK128N7T96Aad32OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK192N12T104Aad288MultiOnce",
        .entry = CaseAEAesGcmK192N12T104Aad288MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK192N12T104Aad288MultiMulti",
        .entry = CaseAEAesGcmK192N12T104Aad288MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK192N12T104Aad288OnceOnce",
        .entry = CaseAEAesGcmK192N12T104Aad288OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK192N12T104Aad288OnceMulti",
        .entry = CaseAEAesGcmK192N12T104Aad288OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK256N7T112Aad512MultiOnce",
        .entry = CaseAEAesGcmK256N7T112Aad512MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK256N7T112Aad512MultiMulti",
        .entry = CaseAEAesGcmK256N7T112Aad512MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK256N7T128Aad512OnceOnce",
        .entry = CaseAEAesGcmK256N7T128Aad512OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK256N7T128Aad512OnceMulti",
        .entry = CaseAEAesGcmK256N7T128Aad512OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK128N12T120Aad4MMultiOnce",
        .entry = CaseAEAesGcmK128N12T120Aad4MMultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK128N12T120Aad4MMultiMulti",
        .entry = CaseAEAesGcmK128N12T120Aad4MMultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK192N7T128Aad32MultiOnce",
        .entry = CaseAEAesGcmK192N7T128Aad32MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK192N7T128Aad32MultiMulti",
        .entry = CaseAEAesGcmK192N7T128Aad32MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK256N7T112Aad512DecryptOnlyTAG",
        .entry = CaseAEAesGcmK256N7T112Aad512DecryptOnlyTAG,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK192N12T96NoAadOnce",
        .entry = CaseAEAesGcmK192N12T96NoAadOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK192N12T96NoAadMulti",
        .entry = CaseAEAesGcmK192N12T96NoAadMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAEAesGcmK128N7T104Aad512EncryptOnlyTAG",
        .entry = CaseAEAesGcmK128N7T104Aad512EncryptOnlyTAG,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T96Aad32MultiOnce",
        .entry = CaseAESM4GcmK128N7T96Aad32MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T96Aad32MultiMulti",
        .entry = CaseAESM4GcmK128N7T96Aad32MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T96Aad32OnceOnce",
        .entry = CaseAESM4GcmK128N7T96Aad32OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T96Aad32OnceMulti",
        .entry = CaseAESM4GcmK128N7T96Aad32OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T96Aad32update0Multi",
        .entry = CaseAESM4GcmK128N7T96Aad32update0Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N12T104Aad288MultiOnce",
        .entry = CaseAESM4GcmK128N12T104Aad288MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N12T104Aad288MultiMulti",
        .entry = CaseAESM4GcmK128N12T104Aad288MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N12T104Aad288OnceOnce",
        .entry = CaseAESM4GcmK128N12T104Aad288OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N12T104Aad288OnceMulti",
        .entry = CaseAESM4GcmK128N12T104Aad288OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T112Aad512MultiOnce",
        .entry = CaseAESM4GcmK128N7T112Aad512MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T112Aad512MultiMulti",
        .entry = CaseAESM4GcmK128N7T112Aad512MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T128Aad512OnceOnce",
        .entry = CaseAESM4GcmK128N7T128Aad512OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T128Aad512OnceMulti",
        .entry = CaseAESM4GcmK128N7T128Aad512OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N12T120Aad4MMultiOnce",
        .entry = CaseAESM4GcmK128N12T120Aad4MMultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N12T120Aad4MMultiMulti",
        .entry = CaseAESM4GcmK128N12T120Aad4MMultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T128Aad32MultiOnce",
        .entry = CaseAESM4GcmK128N7T128Aad32MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T128Aad32MultiMulti",
        .entry = CaseAESM4GcmK128N7T128Aad32MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T112Aad512DecryptOnlyTAG",
        .entry = CaseAESM4GcmK128N7T112Aad512DecryptOnlyTAG,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N12T96NoAadOnce",
        .entry = CaseAESM4GcmK128N12T96NoAadOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N12T96NoAadMulti",
        .entry = CaseAESM4GcmK128N12T96NoAadMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAESM4GcmK128N7T104Aad512EncryptOnlyTAG",
        .entry = CaseAESM4GcmK128N7T104Aad512EncryptOnlyTAG,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    // cases_mac_crypto_basic_cases.c
    {
        .name = "CaseHmacSha256KeySize64OnceOnce",
        .entry = CaseHmacSha256KeySize64OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha256KeySize64OnceMulti",
        .entry = CaseHmacSha256KeySize64OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha256KeySize64MultiOnce",
        .entry = CaseHmacSha256KeySize64MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha256KeySize64MultiMulti",
        .entry = CaseHmacSha256KeySize64MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha384KeySize1024OnceOnce",
        .entry = CaseHmacSha384KeySize1024OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha384KeySize1024OnceMulti",
        .entry = CaseHmacSha384KeySize1024OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha384KeySize1024MultiOnce",
        .entry = CaseHmacSha384KeySize1024MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha384KeySize1024MultiMulti",
        .entry = CaseHmacSha384KeySize1024MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha512KeySize256OnceOnce",
        .entry = CaseHmacSha512KeySize256OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha512KeySize256OnceMulti",
        .entry = CaseHmacSha512KeySize256OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha512KeySize256MultiOnce",
        .entry = CaseHmacSha512KeySize256MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha512KeySize256MultiMulti",
        .entry = CaseHmacSha512KeySize256MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSM3KeySize512OnceOnce",
        .entry = CaseHmacSM3KeySize512OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSM3KeySize512OnceMulti",
        .entry = CaseHmacSM3KeySize512OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSM3KeySize512MultiOnce",
        .entry = CaseHmacSM3KeySize512MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSM3KeySize512MultiMulti",
        .entry = CaseHmacSM3KeySize512MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha256KeySize8192OnceOnce",
        .entry = CaseHmacSha256KeySize8192OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha256KeySize8192OnceMulti",
        .entry = CaseHmacSha256KeySize8192OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha256KeySize8192MultiOnce",
        .entry = CaseHmacSha256KeySize8192MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseHmacSha256KeySize8192MultiMulti",
        .entry = CaseHmacSha256KeySize8192MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize128OnceOnce",
        .entry = CaseCmacAesCbcNopadKeySize128OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize128OnceMulti",
        .entry = CaseCmacAesCbcNopadKeySize128OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize128MultiOnce",
        .entry = CaseCmacAesCbcNopadKeySize128MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize128MultiMulti",
        .entry = CaseCmacAesCbcNopadKeySize128MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize192OnceOnce",
        .entry = CaseCmacAesCbcNopadKeySize192OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize192OnceMulti",
        .entry = CaseCmacAesCbcNopadKeySize192OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize192MultiOnce",
        .entry = CaseCmacAesCbcNopadKeySize192MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize192MultiMulti",
        .entry = CaseCmacAesCbcNopadKeySize192MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize256OnceOnce",
        .entry = CaseCmacAesCbcNopadKeySize256OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize256OnceMulti",
        .entry = CaseCmacAesCbcNopadKeySize256OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize256MultiOnce",
        .entry = CaseCmacAesCbcNopadKeySize256MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseCmacAesCbcNopadKeySize256MultiMulti",
        .entry = CaseCmacAesCbcNopadKeySize256MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    // cases_asym_crypto_basic_cases.c
    {
        .name = "CaseAsymEncryptRsaV15KeySize512Once",
        .entry = CaseAsymEncryptRsaV15KeySize512Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaV15KeySize2048Once",
        .entry = CaseAsymEncryptRsaV15KeySize2048Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaV15KeySize2048Multi",
        .entry = CaseAsymEncryptRsaV15KeySize2048Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaV15KeySize4096Once",
        .entry = CaseAsymEncryptRsaV15KeySize4096Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaV15KeySize4096Multi",
        .entry = CaseAsymEncryptRsaV15KeySize4096Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaOaepSha384KeySize2048Once",
        .entry = CaseAsymEncryptRsaOaepSha384KeySize2048Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaOaepSha384KeySize2048Multi",
        .entry = CaseAsymEncryptRsaOaepSha384KeySize2048Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaOaepSha512KeySize4096Once",
        .entry = CaseAsymEncryptRsaOaepSha512KeySize4096Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaOaepSha512KeySize4096Multi",
        .entry = CaseAsymEncryptRsaOaepSha512KeySize4096Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaNopadKeySize2688Once",
        .entry = CaseAsymEncryptRsaNopadKeySize2688Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaNopadKeySize2688Multi",
        .entry = CaseAsymEncryptRsaNopadKeySize2688Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaNopadKeySize4096Once",
        .entry = CaseAsymEncryptRsaNopadKeySize4096Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptRsaNopadKeySize4096Multi",
        .entry = CaseAsymEncryptRsaNopadKeySize4096Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptSm2PkeDataSize64Once",
        .entry = CaseAsymEncryptSm2PkeDataSize64Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptSm2PkeDataSize64Multi",
        .entry = CaseAsymEncryptSm2PkeDataSize64Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptSm2PkeDataSize470Once",
        .entry = CaseAsymEncryptSm2PkeDataSize470Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptSm2PkeDataSize470Multi",
        .entry = CaseAsymEncryptSm2PkeDataSize470Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptSm2PkeDataSize1024Once",
        .entry = CaseAsymEncryptSm2PkeDataSize1024Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymEncryptSm2PkeDataSize1024Multi",
        .entry = CaseAsymEncryptSm2PkeDataSize1024Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    // cases_asym_sign_basic_cases.c
    {
        .name = "CaseAsymSignRsaV15Sha384KeySize2048Once",
        .entry = CaseAsymSignRsaV15Sha384KeySize2048Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignRsaV15Sha384KeySize2048Multi",
        .entry = CaseAsymSignRsaV15Sha384KeySize2048Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignRsaV15Sha512KeySize4096Once",
        .entry = CaseAsymSignRsaV15Sha512KeySize4096Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignRsaV15Sha512KeySize4096Multi",
        .entry = CaseAsymSignRsaV15Sha512KeySize4096Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignRsaPssSha384KeySize2048Once",
        .entry = CaseAsymSignRsaPssSha384KeySize2048Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignRsaPssSha384KeySize2048Multi",
        .entry = CaseAsymSignRsaPssSha384KeySize2048Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignRsaPssSha512KeySize4096Once",
        .entry = CaseAsymSignRsaPssSha512KeySize4096Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignRsaPssSha512KeySize4096Multi",
        .entry = CaseAsymSignRsaPssSha512KeySize4096Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEcdsaSha256KeySize256Once",
        .entry = CaseAsymSignEcdsaSha256KeySize256Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEcdsaSha256KeySize256Multi",
        .entry = CaseAsymSignEcdsaSha256KeySize256Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEcdsaSha384KeySize384Once",
        .entry = CaseAsymSignEcdsaSha384KeySize384Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEcdsaSha384KeySize384Multi",
        .entry = CaseAsymSignEcdsaSha384KeySize384Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEcdsaSha512KeySize521Once",
        .entry = CaseAsymSignEcdsaSha512KeySize521Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEcdsaSha512KeySize521Multi",
        .entry = CaseAsymSignEcdsaSha512KeySize521Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEd25519DataSize64Once",
        .entry = CaseAsymSignEd25519DataSize64Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEd25519DataSize64Multi",
        .entry = CaseAsymSignEd25519DataSize64Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEd25519DataSize470Once",
        .entry = CaseAsymSignEd25519DataSize470Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEd25519DataSize470Multi",
        .entry = CaseAsymSignEd25519DataSize470Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEd25519DataSize1270Once",
        .entry = CaseAsymSignEd25519DataSize1270Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEd25519DataSize1270Multi",
        .entry = CaseAsymSignEd25519DataSize1270Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEd25519DataSize4096Once",
        .entry = CaseAsymSignEd25519DataSize4096Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignEd25519DataSize4096Multi",
        .entry = CaseAsymSignEd25519DataSize4096Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignSm2DsaSm3DataSize32Once",
        .entry = CaseAsymSignSm2DsaSm3DataSize32Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignSm2DsaSm3DataSize128Once",
        .entry = CaseAsymSignSm2DsaSm3DataSize128Once,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseAsymSignSm2DsaSm3DataSize32Multi",
        .entry = CaseAsymSignSm2DsaSm3DataSize32Multi,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    // cases_digest_crypto_basic_cases.c
    {
        .name = "CaseDigestSha256OnceOnce",
        .entry = CaseDigestSha256OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha256OnceMulti",
        .entry = CaseDigestSha256OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha256MultiOnce",
        .entry = CaseDigestSha256MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha256MultiMulti",
        .entry = CaseDigestSha256MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha384OnceOnce",
        .entry = CaseDigestSha384OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha384OnceMulti",
        .entry = CaseDigestSha384OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha384MultiOnce",
        .entry = CaseDigestSha384MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha384MultiMulti",
        .entry = CaseDigestSha384MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha512OnceOnce",
        .entry = CaseDigestSha512OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha512OnceMulti",
        .entry = CaseDigestSha512OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha512MultiOnce",
        .entry = CaseDigestSha512MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSha512MultiMulti",
        .entry = CaseDigestSha512MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSM3OnceOnce",
        .entry = CaseDigestSM3OnceOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSM3OnceMulti",
        .entry = CaseDigestSM3OnceMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSM3MultiOnce",
        .entry = CaseDigestSM3MultiOnce,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDigestSM3MultiMulti",
        .entry = CaseDigestSM3MultiMulti,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    // cases_derive_basic_cases.c
    {
        .name = "CaseDREcdhNistP224DataSize14",
        .entry = CaseDREcdhNistP224DataSize14,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDREcdhNistP256DataSize128",
        .entry = CaseDREcdhNistP256DataSize128,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDREcdhNistP384DataSize512",
        .entry = CaseDREcdhNistP384DataSize512,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDREcdhNistP521DataSize1024",
        .entry = CaseDREcdhNistP521DataSize1024,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDREcdhNistP521DataSize4096",
        .entry = CaseDREcdhNistP521DataSize4096,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDREcdhNistP384DataSize10000",
        .entry = CaseDREcdhNistP384DataSize10000,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDRDHKeySize512Pram512DataSize1024",
        .entry = CaseDRDHKeySize512Pram512DataSize1024,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDRDHKeySize1024Pram1024DataSize1024",
        .entry = CaseDRDHKeySize1024Pram1024DataSize1024,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDRX25519DataSize1024",
        .entry = CaseDRX25519DataSize1024,
        .ranFlag = CASE_RAN_FLAG_CLEAR,
        .ret = -1,
    },
    {
        .name = "CaseDRX25519DataSize4096",
        .entry = CaseDRX25519DataSize4096,
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