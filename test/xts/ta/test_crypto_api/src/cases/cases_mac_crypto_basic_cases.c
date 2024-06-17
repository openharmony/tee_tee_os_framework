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

/*
 * Case name meaning: Case&&Algname&&Compute mode&&Compute times
 * Compute mode: number of calculateing steps, once means datasize is less than slicesize,
   multi means datasize is greater than slicesize
 * Compute times: algorithm calculation times, once means algorithm calculation once,
   multi means algorithm calculation multi times
 */

// Crypto_MAC_Fun_003
int CaseHmacSha256KeySize64OnceOnce(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha256"},
        .operaMaxKeySize = 64,
        .keySize = 64,
        .fwdKeyTypeName = "kt_hmac_sha256",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA50K_LE64B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha256KeySize64OnceOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_004
int CaseHmacSha256KeySize64OnceMulti(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha256"},
        .operaMaxKeySize = 64,
        .keySize = 64,
        .fwdKeyTypeName = "kt_hmac_sha256",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA50K_LE64B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha256KeySize64OnceMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_001
int CaseHmacSha256KeySize64MultiOnce(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha256"},
        .operaMaxKeySize = 64,
        .keySize = 64,
        .fwdKeyTypeName = "kt_hmac_sha256",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA50K_GR64B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha256KeySize64MultiOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_002
int CaseHmacSha256KeySize64MultiMulti(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha256"},
        .operaMaxKeySize = 64,
        .keySize = 64,
        .fwdKeyTypeName = "kt_hmac_sha256",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA50K_GR64B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha256KeySize64MultiMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_003
int CaseHmacSha512KeySize256OnceOnce(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha512"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_hmac_sha512",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA500K_LE1B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha512KeySize256OnceOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_004
int CaseHmacSha512KeySize256OnceMulti(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha512"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_hmac_sha512",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA500K_LE1B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha512KeySize256OnceMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_001
int CaseHmacSha512KeySize256MultiOnce(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha512"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_hmac_sha512",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA500K_GR1B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha512KeySize256MultiOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_002
int CaseHmacSha512KeySize256MultiMulti(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha512"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_hmac_sha512",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA500K_GR1B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha512KeySize256MultiMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_003
int CaseHmacSM3KeySize512OnceOnce(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sm3"},
        .operaMaxKeySize = 512,
        .keySize = 512,
        .fwdKeyTypeName = "kt_hmac_sm3",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA1M_LE1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSM3KeySize512OnceOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_004
int CaseHmacSM3KeySize512OnceMulti(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sm3"},
        .operaMaxKeySize = 512,
        .keySize = 512,
        .fwdKeyTypeName = "kt_hmac_sm3",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA1M_LE1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSM3KeySize512OnceMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_001
int CaseHmacSM3KeySize512MultiOnce(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sm3"},
        .operaMaxKeySize = 512,
        .keySize = 512,
        .fwdKeyTypeName = "kt_hmac_sm3",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA2M,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSM3KeySize512MultiOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_002
int CaseHmacSM3KeySize512MultiMulti(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sm3"},
        .operaMaxKeySize = 512,
        .keySize = 512,
        .fwdKeyTypeName = "kt_hmac_sm3",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA2M,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSM3KeySize512MultiMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_003
int CaseHmacSha384KeySize1024OnceOnce(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha384"},
        .operaMaxKeySize = 1024,
        .keySize = 1024,
        .fwdKeyTypeName = "kt_hmac_sha384",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA500K_LE128B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha384KeySize1024OnceOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_004
int CaseHmacSha384KeySize1024OnceMulti(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha384"},
        .operaMaxKeySize = 1024,
        .keySize = 1024,
        .fwdKeyTypeName = "kt_hmac_sha384",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA500K_LE128B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha384KeySize1024OnceMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_001
int CaseHmacSha384KeySize1024MultiOnce(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha384"},
        .operaMaxKeySize = 1024,
        .keySize = 1024,
        .fwdKeyTypeName = "kt_hmac_sha384",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = SLICELEN_500K,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha384KeySize1024MultiOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_002
int CaseHmacSha384KeySize1024MultiMulti(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha384"},
        .operaMaxKeySize = 1024,
        .keySize = 1024,
        .fwdKeyTypeName = "kt_hmac_sha384",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = SLICELEN_500K,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha384KeySize1024MultiMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_003
int CaseHmacSha256KeySize8192OnceOnce(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha256"},
        .operaMaxKeySize = 8192,
        .keySize = 8192,
        .fwdKeyTypeName = "kt_hmac_sha256",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA1M_LE1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha256KeySize8192OnceOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_004
int CaseHmacSha256KeySize8192OnceMulti(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha256"},
        .operaMaxKeySize = 8192,
        .keySize = 8192,
        .fwdKeyTypeName = "kt_hmac_sha256",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA1M_LE1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha256KeySize8192OnceMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_001
int CaseHmacSha256KeySize8192MultiOnce(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha256"},
        .operaMaxKeySize = 8192,
        .keySize = 8192,
        .fwdKeyTypeName = "kt_hmac_sha256",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA1M_GR1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha256KeySize8192MultiOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_002
int CaseHmacSha256KeySize8192MultiMulti(void)
{
    TestVector tv = {
        .algName = {"M_hmac_sha256"},
        .operaMaxKeySize = 8192,
        .keySize = 8192,
        .fwdKeyTypeName = "kt_hmac_sha256",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA1M_GR1B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseHmacSha256KeySize8192MultiMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_007
int CaseCmacAesCbcNopadKeySize128OnceOnce(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
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
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize128OnceOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_008
int CaseCmacAesCbcNopadKeySize128OnceMulti(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
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
            MInitFwd, MComputeFwd,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize128OnceMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_005
int CaseCmacAesCbcNopadKeySize128MultiOnce(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
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
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize128MultiOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_006
int CaseCmacAesCbcNopadKeySize128MultiMulti(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
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
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize128MultiMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_007
int CaseCmacAesCbcNopadKeySize192OnceOnce(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
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
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize192OnceOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_008
int CaseCmacAesCbcNopadKeySize192OnceMulti(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
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
            MInitFwd, MComputeFwd,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize192OnceMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_005
int CaseCmacAesCbcNopadKeySize192MultiOnce(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
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
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize192MultiOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_006
int CaseCmacAesCbcNopadKeySize192MultiMulti(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
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
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize192MultiMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_007
int CaseCmacAesCbcNopadKeySize256OnceOnce(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = SLICELEN_500K,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize256OnceOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_008
int CaseCmacAesCbcNopadKeySize256OnceMulti(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = SLICELEN_500K,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MComputeFwd,
            MInitFwd, MComputeFwd,
            MInitBck, MCapareBck,
            MInitBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize256OnceMulti success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_005
int CaseCmacAesCbcNopadKeySize256MultiOnce(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA1M_GR16B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize256MultiOnce success\n", __func__);
    return 0;
}

// Crypto_MAC_Fun_006
int CaseCmacAesCbcNopadKeySize256MultiMulti(void)
{
    TestVector tv = {
        .algName = {"M_aes_cbc_nopad"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_aes",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .ivLen = 16,
        .dataSize = DATA1M_GR16B,
        .sliceSize = SLICELEN_1M,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitFwd, MUpdateFwd, MComputeFwd,
            MInitBck, MUpdateBck, MCapareBck,
            MInitBck, MUpdateBck, MCapareBck,
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
    tlogi("[%s]:--------------CaseCmacAesCbcNopadKeySize256MultiMulti success\n", __func__);
    return 0;
}