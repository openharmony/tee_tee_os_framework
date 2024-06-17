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

#include "monad.h"
#include "tee_log.h"

// Crypto_AE_Fun_001
int CaseAEAesCcmK128N7T32Aad32MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 32,
        .aeTagOSize = 4,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK128N7T32Aad32MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_002
int CaseAEAesCcmK128N7T32Aad32MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 32,
        .aeTagOSize = 4,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK128N7T32Aad32MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_002
int CaseAEAesCcmK128N7T32Aad32update0Multi(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 32,
        .aeTagOSize = 4,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdate0Fwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdate0Bck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdate0Fwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdate0Bck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 25,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK128N7T32Aad32update0Multi success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_003
int CaseAEAesCcmK128N7T32Aad32OnceOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 32,
        .aeTagOSize = 4,
        .sliceSize = SLICELEN_500K,
        .dataSize = DATA500K_LE1B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK128N7T32Aad32OnceOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_004
int CaseAEAesCcmK128N7T32Aad32OnceMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 32,
        .aeTagOSize = 4,
        .sliceSize = SLICELEN_500K,
        .dataSize = DATA500K_LE1B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK128N7T32Aad32OnceMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_001
int CaseAEAesCcmK192N8T48Aad288MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 8,
        .nonceByte = 0x11,
        .aeTagLen = 48,
        .aeTagOSize = 6,
        .sliceSize = SLICELEN_100K_GR200B,
        .dataSize = DATA100K_GR500B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK192N8T48Aad288MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_002
int CaseAEAesCcmK192N8T48Aad288MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 8,
        .nonceByte = 0x11,
        .aeTagLen = 48,
        .aeTagOSize = 6,
        .sliceSize = SLICELEN_100K_GR200B,
        .dataSize = DATA100K_GR500B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK192N8T48Aad288MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_003
int CaseAEAesCcmK192N8T48Aad288OnceOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 8,
        .nonceByte = 0x11,
        .aeTagLen = 48,
        .aeTagOSize = 6,
        .sliceSize = SLICELEN_100K_GR200B,
        .dataSize = DATA100K_LE1B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK192N8T48Aad288OnceOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_004
int CaseAEAesCcmK192N8T48Aad288OnceMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 8,
        .nonceByte = 0x11,
        .aeTagLen = 48,
        .aeTagOSize = 6,
        .sliceSize = SLICELEN_100K_GR200B,
        .dataSize = DATA100K_LE1B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK192N8T48Aad288OnceMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_001
int CaseAEAesCcmK256N9T64Aad512MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 9,
        .nonceByte = 0x12,
        .aeTagLen = 64,
        .aeTagOSize = 8,
        .sliceSize = SLICELEN_250K_GR200B,
        .dataSize = DATA250K_GR200B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK256N9T64Aad512MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_002
int CaseAEAesCcmK256N9T64Aad512MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 9,
        .nonceByte = 0x12,
        .aeTagLen = 64,
        .aeTagOSize = 8,
        .sliceSize = SLICELEN_250K_GR200B,
        .dataSize = DATA250K_GR200B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK256N9T64Aad512MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_003
int CaseAEAesCcmK256N13T128Aad512OnceOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 13,
        .nonceByte = 0x12,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_LE16B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK256N13T128Aad512OnceOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_004
int CaseAEAesCcmK256N13T128Aad512OnceMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 13,
        .nonceByte = 0x12,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_LE16B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadMtlFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK256N13T128Aad512OnceMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_001
int CaseAEAesCcmK128N10T80Aad4MMultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 10,
        .nonceByte = 0x13,
        .aeTagLen = 80,
        .aeTagOSize = 10,
        .sliceSize = SLICELEN_500K,
        .dataSize = SLICELEN_500K,
        .aeAadLen = 4096,
        .aeAadLenInit = 4096,
        .aadByte = 0x13,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK128N10T80Aad4MMultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_002
int CaseAEAesCcmK128N10T80Aad4MMultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 10,
        .nonceByte = 0x13,
        .aeTagLen = 80,
        .aeTagOSize = 10,
        .sliceSize = SLICELEN_500K,
        .dataSize = SLICELEN_500K,
        .aeAadLen = 4096,
        .aeAadLenInit = 4096,
        .aadByte = 0x13,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK128N10T80Aad4MMultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_001
int CaseAEAesCcmK192N11T96Aad32MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 11,
        .nonceByte = 0x14,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_250K_GR200B,
        .dataSize = DATA250K_GR200B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x14,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK192N11T96AadMAXMultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_002
int CaseAEAesCcmK192N11T96Aad32MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 11,
        .nonceByte = 0x14,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_250K_GR200B,
        .dataSize = DATA250K_GR200B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x14,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK192N11T96AadMAXMultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_001
int CaseAEAesCcmK256N12T112Aad288MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x15,
        .aeTagLen = 112,
        .aeTagOSize = 14,
        .sliceSize = SLICELEN_100K_GR200B,
        .dataSize = DATA100K_GR500B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x15,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK256N12T112Aad288MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_002
int CaseAEAesCcmK256N12T112Aad288MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x15,
        .aeTagLen = 112,
        .aeTagOSize = 14,
        .sliceSize = SLICELEN_100K_GR200B,
        .dataSize = DATA100K_GR500B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x15,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK256N12T112Aad288MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_001
int CaseAEAesCcmK128N13T128Aad512MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 13,
        .nonceByte = 0x16,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x16,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK256N12T112Aad288MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_002
int CaseAEAesCcmK128N13T128Aad512MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 13,
        .nonceByte = 0x16,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x16,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK128N13T128Aad512MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_008
int CaseAEAesCcmK256N9T64Aad512DecryptOnlyTAG(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 9,
        .nonceByte = 0x17,
        .aeTagLen = 64,
        .aeTagOSize = 8,
        .sliceSize = SLICELEN_500K,
        .dataSize = SLICELEN_500K,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x17,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalOmtBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK256N9T64Aad512DecryptOnlyTAG success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_005
int CaseAEAesCcmK192N8T64NoAadOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 8,
        .nonceByte = 0x18,
        .aeTagLen = 64,
        .aeTagOSize = 8,
        .sliceSize = SLICELEN_500K,
        .dataSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK192N8T64NoAadOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_006
int CaseAEAesCcmK192N8T64NoAadMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 8,
        .nonceByte = 0x19,
        .aeTagLen = 64,
        .aeTagOSize = 8,
        .sliceSize = SLICELEN_500K,
        .dataSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK192N8T64NoAadMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_007
int CaseAEAesCcmK128N7T32Aad512EncryptOnlyTAG(void)
{
    TestVector tv = {
        .algName = {"AE_aes_ccm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x20,
        .aeTagLen = 32,
        .aeTagOSize = 4,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x20,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalOmtFwd,
            GlbFree,
            IRTearDown, },
        .actionsSize = 9,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesCcmK128N7T32Aad512EncryptOnlyTAG success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_009
int CaseAEAesGcmK128N7T96Aad32MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK128N7T96Aad32MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_010
int CaseAEAesGcmK128N7T96Aad32MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK128N7T96Aad32MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_010
int CaseAEAesGcmK128N7T96Aad32update0Multi(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdate0Fwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdate0Bck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdate0Fwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdate0Bck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 25,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK128N7T96Aad32update0Multi success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_011
int CaseAEAesGcmK128N7T96Aad32OnceOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_LE16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK128N7T96Aad32OnceOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_012
int CaseAEAesGcmK128N7T96Aad32OnceMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_LE16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK128N7T96Aad32OnceMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_009
int CaseAEAesGcmK192N12T104Aad288MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x11,
        .aeTagLen = 104,
        .aeTagOSize = 13,
        .sliceSize = SLICELEN_100K_GR200B,
        .dataSize = DATA100K_GR500B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK192N12T104Aad288MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_010
int CaseAEAesGcmK192N12T104Aad288MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x11,
        .aeTagLen = 104,
        .aeTagOSize = 13,
        .sliceSize = SLICELEN_100K_GR200B,
        .dataSize = DATA100K_GR500B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK192N12T104Aad288MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_011
int CaseAEAesGcmK192N12T104Aad288OnceOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x11,
        .aeTagLen = 104,
        .aeTagOSize = 13,
        .sliceSize = SLICELEN_500K,
        .dataSize = DATA500K_LE1B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK192N12T104Aad288OnceOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_012
int CaseAEAesGcmK192N12T104Aad288OnceMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x11,
        .aeTagLen = 104,
        .aeTagOSize = 13,
        .sliceSize = SLICELEN_500K,
        .dataSize = DATA500K_LE1B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK192N12T104Aad288OnceMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_009
int CaseAEAesGcmK256N7T112Aad512MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x12,
        .aeTagLen = 112,
        .aeTagOSize = 14,
        .sliceSize = SLICELEN_250K_GR200B,
        .dataSize = DATA250K_GR200B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK256N7T112Aad512MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_010
int CaseAEAesGcmK256N7T112Aad512MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x12,
        .aeTagLen = 112,
        .aeTagOSize = 14,
        .sliceSize = SLICELEN_250K_GR200B,
        .dataSize = DATA250K_GR200B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK256N7T112Aad512MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_011
int CaseAEAesGcmK256N7T128Aad512OnceOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x12,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_1M,
        .dataSize = DATA1M_LE1B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK256N7T128Aad512OnceOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_012
int CaseAEAesGcmK256N7T128Aad512OnceMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x12,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_1M,
        .dataSize = DATA1M_LE1B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadMtlFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK256N7T128Aad512OnceMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_009
int CaseAEAesGcmK128N12T120Aad4MMultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x13,
        .aeTagLen = 120,
        .aeTagOSize = 15,
        .sliceSize = SLICELEN_500K,
        .dataSize = SLICELEN_500K,
        .aeAadLen = 4096,
        .aeAadLenInit = 4096,
        .aadByte = 0x13,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK128N12T120Aad4MMultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_010
int CaseAEAesGcmK128N12T120Aad4MMultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x13,
        .aeTagLen = 120,
        .aeTagOSize = 15,
        .sliceSize = SLICELEN_500K,
        .dataSize = SLICELEN_500K,
        .aeAadLen = 4096,
        .aeAadLenInit = 4096,
        .aadByte = 0x13,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK128N12T120Aad4MMultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_009
int CaseAEAesGcmK192N7T128Aad32MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x14,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x14,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK192N7T128Aad32MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_010
int CaseAEAesGcmK192N7T128Aad32MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x14,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x14,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK192N7T128Aad32MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_016
int CaseAEAesGcmK256N7T112Aad512DecryptOnlyTAG(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x17,
        .aeTagLen = 112,
        .aeTagOSize = 14,
        .sliceSize = SLICELEN_1M,
        .dataSize = DATA1M_GR1B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x17,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalOmtBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK256N7T112Aad512DecryptOnlyTAG success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_013
int CaseAEAesGcmK192N12T96NoAadOnce(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x18,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_500K,
        .dataSize = DATA500K_GR1B,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK192N12T96NoAadOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_014
int CaseAEAesGcmK192N12T96NoAadMulti(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x18,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_500K,
        .dataSize = DATA500K_GR1B,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK192N12T96NoAadMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_015
int CaseAEAesGcmK128N7T104Aad512EncryptOnlyTAG(void)
{
    TestVector tv = {
        .algName = {"AE_aes_gcm"},
        .operaMaxKeySize = 256,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x20,
        .aeTagLen = 104,
        .aeTagOSize = 13,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x20,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalOmtFwd,
            GlbFree,
            IRTearDown, },
        .actionsSize = 9,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAEAesGcmK128N7T104Aad512EncryptOnlyTAG success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_017
int CaseAESM4GcmK128N7T96Aad32MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T96Aad32MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_018
int CaseAESM4GcmK128N7T96Aad32MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T96Aad32MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_019
int CaseAESM4GcmK128N7T96Aad32OnceOnce(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_LE16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T96Aad32OnceOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_020
int CaseAESM4GcmK128N7T96Aad32OnceMulti(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_LE16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T96Aad32OnceMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_018
int CaseAESM4GcmK128N7T96Aad32update0Multi(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x10,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x10,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdate0Fwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdate0Bck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdate0Fwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdate0Bck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 25,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T96Aad32update0Multi success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_017
int CaseAESM4GcmK128N12T104Aad288MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x11,
        .aeTagLen = 104,
        .aeTagOSize = 13,
        .sliceSize = SLICELEN_100K_GR200B,
        .dataSize = DATA100K_GR500B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N12T104Aad288MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_018
int CaseAESM4GcmK128N12T104Aad288MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x11,
        .aeTagLen = 104,
        .aeTagOSize = 13,
        .sliceSize = SLICELEN_100K_GR200B,
        .dataSize = DATA100K_GR500B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N12T104Aad288MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_019
int CaseAESM4GcmK128N12T104Aad288OnceOnce(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x11,
        .aeTagLen = 104,
        .aeTagOSize = 13,
        .sliceSize = SLICELEN_500K,
        .dataSize = DATA500K_LE1B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N12T104Aad288OnceOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_020
int CaseAESM4GcmK128N12T104Aad288OnceMulti(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x11,
        .aeTagLen = 104,
        .aeTagOSize = 13,
        .sliceSize = SLICELEN_500K,
        .dataSize = DATA500K_LE1B,
        .aeAadLen = 288,
        .aeAadLenInit = 288,
        .aadByte = 0x11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N12T104Aad288OnceMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_017
int CaseAESM4GcmK128N7T112Aad512MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x12,
        .aeTagLen = 112,
        .aeTagOSize = 14,
        .sliceSize = SLICELEN_250K_GR200B,
        .dataSize = DATA250K_GR200B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T112Aad512MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_018
int CaseAESM4GcmK128N7T112Aad512MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x12,
        .aeTagLen = 112,
        .aeTagOSize = 14,
        .sliceSize = SLICELEN_250K_GR200B,
        .dataSize = DATA250K_GR200B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T112Aad512MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_019
int CaseAESM4GcmK128N7T128Aad512OnceOnce(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x12,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_1M,
        .dataSize = DATA1M_LE1B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T128Aad512OnceOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_020
int CaseAESM4GcmK128N7T128Aad512OnceMulti(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x12,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_1M,
        .dataSize = DATA1M_LE1B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x12,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadMtlFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T128Aad512OnceMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_017
int CaseAESM4GcmK128N12T120Aad4MMultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x13,
        .aeTagLen = 120,
        .aeTagOSize = 15,
        .sliceSize = SLICELEN_500K,
        .dataSize = SLICELEN_500K,
        .aeAadLen = 4096,
        .aeAadLenInit = 4096,
        .aadByte = 0x13,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N12T120Aad4MMultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_018
int CaseAESM4GcmK128N12T120Aad4MMultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x13,
        .aeTagLen = 120,
        .aeTagOSize = 15,
        .sliceSize = SLICELEN_500K,
        .dataSize = SLICELEN_500K,
        .aeAadLen = 4096,
        .aeAadLenInit = 4096,
        .aadByte = 0x13,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N12T120Aad4MMultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_017
int CaseAESM4GcmK128N7T128Aad32MultiOnce(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x14,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_1M,
        .dataSize = DATA1M_GR1B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x14,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T128Aad32MultiOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_018
int CaseAESM4GcmK128N7T128Aad32MultiMulti(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x14,
        .aeTagLen = 128,
        .aeTagOSize = 16,
        .sliceSize = SLICELEN_1M,
        .dataSize = DATA1M_GR1B,
        .aeAadLen = 32,
        .aeAadLenInit = 32,
        .aadByte = 0x14,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateAadFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 21,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T128Aad32MultiMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_017
int CaseAESM4GcmK128N7T112Aad512DecryptOnlyTAG(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x17,
        .aeTagLen = 112,
        .aeTagOSize = 14,
        .sliceSize = SLICELEN_1M,
        .dataSize = DATA1M_GR1B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x17,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateAadMtlBck, AEUpdateBck, AEDoFinalOmtBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 13,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T112Aad512DecryptOnlyTAG success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_018
int CaseAESM4GcmK128N12T96NoAadOnce(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x18,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_500K,
        .dataSize = DATA500K_GR1B,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 11,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N12T96NoAadOnce success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_017
int CaseAESM4GcmK128N12T96NoAadMulti(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 12,
        .nonceByte = 0x18,
        .aeTagLen = 96,
        .aeTagOSize = 12,
        .sliceSize = SLICELEN_500K,
        .dataSize = DATA500K_GR1B,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateBck, AEDoFinalBck,
            AEInitFwd, AEUpdateFwd, AEEncFinalFwd,
            AEInitBck, AEUpdateBck, AEDoFinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 17,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N12T96NoAadMulti success\n", __func__);
    return 0;
}

// Crypto_AE_Fun_018
int CaseAESM4GcmK128N7T104Aad512EncryptOnlyTAG(void)
{
    TestVector tv = {
        .algName = {"AE_sm4_gcm"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .aeNonceLen = 7,
        .nonceByte = 0x20,
        .aeTagLen = 104,
        .aeTagOSize = 13,
        .sliceSize = SLICELEN_50K,
        .dataSize = DATA50K_GR16B,
        .aeAadLen = 512,
        .aeAadLenInit = 512,
        .aadByte = 0x20,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            AEInitFwd, AEUpdateAadMtlFwd, AEUpdateFwd, AEEncFinalOmtFwd,
            GlbFree,
            IRTearDown, },
        .actionsSize = 9,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAESM4GcmK128N7T104Aad512EncryptOnlyTAG success\n", __func__);
    return 0;
}