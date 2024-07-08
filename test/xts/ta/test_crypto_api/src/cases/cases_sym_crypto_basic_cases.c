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

// Crypto_Sym_Fun_003
int CaseSymEncryptAesEcbNopadKeySize128OnceOnce(void)
{
    TestVector tv = {
        .algName = {"SC_aes_ecb_nopad"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_LE16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesEcbNopadKeySize128OnceOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_004
int CaseSymEncryptAesEcbNopadKeySize128OnceMulti(void)
{
    TestVector tv = {
        .algName = {"SC_aes_ecb_nopad"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_LE16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesEcbNopadKeySize128OnceMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_001
int CaseSymEncryptAesEcbNopadKeySize128MultiOnce(void)
{
    TestVector tv = {
        .algName = {"SC_aes_ecb_nopad"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_GR16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesEcbNopadKeySize128MultiOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_001
int CaseSymEncryptAesEcbNopadKeySize128MultiMulti(void)
{
    TestVector tv = {
        .algName = {"SC_aes_ecb_nopad"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_GR16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesEcbNopadKeySize128MultiMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_003
int CaseSymEncryptAesCbcNopadKeySize192OnceOnce(void)
{
    TestVector tv = {
        .algName = {"SC_aes_cbc_nopad"},
        .operaMaxKeySize = 192,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA500K_LE16B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCbcNopadKeySize192OnceOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_004
int CaseSymEncryptAesCbcNopadKeySize192OnceMulti(void)
{
    TestVector tv = {
        .algName = {"SC_aes_cbc_nopad"},
        .operaMaxKeySize = 192,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA500K_LE16B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCbcNopadKeySize192OnceMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_001
int CaseSymEncryptAesCbcNopadKeySize192MultiOnce(void)
{
    TestVector tv = {
        .algName = {"SC_aes_cbc_nopad"},
        .operaMaxKeySize = 192,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = SLICELEN_500K,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCbcNopadKeySize192MultiOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_001
int CaseSymEncryptAesCbcNopadKeySize192MultiMulti(void)
{
    TestVector tv = {
        .algName = {"SC_aes_cbc_nopad"},
        .operaMaxKeySize = 192,
        .keySize = 192,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = SLICELEN_500K,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCbcNopadKeySize192MultiMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_003
int CaseSymEncryptAesCtrKeySize128OnceOnce(void)
{
    TestVector tv = {
        .algName = {"SC_aes_ctr"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_LE16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCtrKeySize128OnceOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_004
int CaseSymEncryptAesCtrKeySize128OnceMulti(void)
{
    TestVector tv = {
        .algName = {"SC_aes_ctr"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_LE16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCtrKeySize128OnceMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_001
int CaseSymEncryptAesCtrKeySize128MultiOnce(void)
{
    TestVector tv = {
        .algName = {"SC_aes_ctr"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_GR16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCtrKeySize128MultiOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_001
int CaseSymEncryptAesCtrKeySize128MultiMulti(void)
{
    TestVector tv = {
        .algName = {"SC_aes_ctr"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_GR16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCtrKeySize128MultiMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_003
int CaseSymEncryptAesXtsKeySize256OnceOnce(void)
{
    TestVector tv = {
        .algName = {"SC_aes_xts"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = 256,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesXtsKeySize256OnceOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_004
int CaseSymEncryptAesXtsKeySize256OnceMulti(void)
{
    TestVector tv = {
        .algName = {"SC_aes_xts"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = 256,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesXtsKeySize256OnceMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_001
int CaseSymEncryptAesXtsKeySize256MultiOnce(void)
{
    TestVector tv = {
        .algName = {"SC_aes_xts"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = SLICELEN_500K,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesXtsKeySize256MultiOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_001
int CaseSymEncryptAesXtsKeySize256MultiMulti(void)
{
    TestVector tv = {
        .algName = {"SC_aes_xts"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = SLICELEN_500K,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesXtsKeySize256MultiMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_003
int CaseSymEncryptAesCbcPkcs5KeySize256OnceOnce(void)
{
    TestVector tv = {
        .algName = {"SC_aes_cbc_pkcs5"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA1M_LE1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp, GlbAlloc, 
            GlbCopy, GlbGetInfo, 
            GlbGetInfoMulti, GlbIsAlgSprt, 
            GlbS1S2, SCInitFwd, 
            SCDofinalFwd, SCInitBck, 
            SCDofinalBck, GlbReset, 
            GlbFree, IRTearDown, },
        .actionsSize = 14,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseSymEncryptAesCbcPkcs5KeySize256OnceOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_004
int CaseSymEncryptAesCbcPkcs5KeySize256OnceMulti(void)
{
    TestVector tv = {
        .algName = {"SC_aes_cbc_pkcs5"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA1M_LE1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCbcPkcs5KeySize256OnceMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_001
int CaseSymEncryptAesCbcPkcs5KeySize256MultiOnce(void)
{
    TestVector tv = {
        .algName = {"SC_aes_cbc_pkcs5"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA1M_GR1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCbcPkcs5KeySize256MultiOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_001
int CaseSymEncryptAesCbcPkcs5KeySize256MultiMulti(void)
{
    TestVector tv = {
        .algName = {"SC_aes_cbc_pkcs5"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA1M_GR1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptAesCbcPkcs5KeySize256MultiMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_007
int CaseSymEncryptSm4CbcNopadKeySize128OnceOnce(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cbc_nopad"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_LE16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CbcNopadKeySize128OnceOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_008
int CaseSymEncryptSm4CbcNopadKeySize128OnceMulti(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cbc_nopad"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_LE16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CbcNopadKeySize128OnceMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_005
int CaseSymEncryptSm4CbcNopadKeySize128MultiOnce(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cbc_nopad"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_GR16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CbcNopadKeySize128MultiOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_006
int CaseSymEncryptSm4CbcNopadKeySize128MultiMulti(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cbc_nopad"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_GR16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CbcNopadKeySize128MultiMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_007
int CaseSymEncryptSm4CtrKeySize128OnceOnce(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_ctr"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA1M_LE1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CtrKeySize128OnceOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_008
int CaseSymEncryptSm4CtrKeySize128OnceMulti(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_ctr"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA1M_LE1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CtrKeySize128OnceMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_005
int CaseSymEncryptSm4CtrKeySize128MultiOnce(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_ctr"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA1M_GR1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CtrKeySize128MultiOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_006
int CaseSymEncryptSm4CtrKeySize128MultiMulti(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_ctr"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA1M_GR1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CtrKeySize128MultiMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_007
int CaseSymEncryptSm4Cfb128KeySize128OnceOnce(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cfb128"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA500K_LE1B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4Cfb128KeySize128OnceOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_008
int CaseSymEncryptSm4Cfb128KeySize128OnceMulti(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cfb128"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA500K_LE1B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4Cfb128KeySize128OnceMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_005
int CaseSymEncryptSm4Cfb128KeySize128MultiOnce(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cfb128"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = SLICELEN_500K,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4Cfb128KeySize128MultiOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_006
int CaseSymEncryptSm4Cfb128KeySize128MultiMulti(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cfb128"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = SLICELEN_500K,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4Cfb128KeySize128MultiMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_007
int CaseSymEncryptSm4CbcPkcs7KeySize128OnceOnce(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cbc_pkcs7"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_LE16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CbcPkcs7KeySize128OnceOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_008
int CaseSymEncryptSm4CbcPkcs7KeySize128OnceMulti(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cbc_pkcs7"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_LE16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCDofinalFwd,
            SCInitFwd, SCDofinalFwd,
            SCInitBck, SCDofinalBck,
            SCInitBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CbcPkcs7KeySize128OnceMulti success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_005
int CaseSymEncryptSm4CbcPkcs7KeySize128MultiOnce(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cbc_pkcs7"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_GR16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CbcPkcs7KeySize128MultiOnce success\n", __func__);
    return 0;
}

// Crypto_Sym_Fun_006
int CaseSymEncryptSm4CbcPkcs7KeySize128MultiMulti(void)
{
    TestVector tv = {
        .algName = {"SC_sm4_cbc_pkcs7"},
        .operaMaxKeySize = 128,
        .keySize = 128,
        .fwdKeyTypeName = "kt_sm4",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA50K_GR16B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitFwd, SCUpdateFwd, SCDofinalFwd,
            SCInitBck, SCUpdateBck, SCDofinalBck,
            SCInitBck, SCUpdateBck, SCDofinalBck,
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
    tlogi("[%s]:--------------CaseSymEncryptSm4CbcPkcs7KeySize128MultiMulti success\n", __func__);
    return 0;
}
