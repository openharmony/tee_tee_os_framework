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
 * Case name meaning: Case&&algname&&Compute mode&&Compute times
 * Compute mode: number of calculateing steps, once means datasize is less than slicesize,
   multi means datasize is greater than slicesize
 * Compute times: algorithm calculation times, once means algorithm calculation once,
   multi means algorithm calculation multi times
 */

// Crypto_DI_Fun_002
int CaseDigestSha256OnceOnce(void)
{
    TestVector tv = {
        .algName = {"DI_sha256"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA50K_LE64B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIDofinalFwd, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 6,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha256OnceOnce success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_004
int CaseDigestSha256OnceMulti(void)
{
    TestVector tv = {
        .algName = {"DI_sha256"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA50K_LE64B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIDofinalFwd, DIDofinalFwd,
            DIDofinalBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 8,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha256OnceMulti success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_001
int CaseDigestSha256MultiOnce(void)
{
    TestVector tv = {
        .algName = {"DI_sha256"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA50K_GR64B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 8,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha256MultiOnce success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_003
int CaseDigestSha256MultiMulti(void)
{
    TestVector tv = {
        .algName = {"DI_sha256"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA50K_GR64B,
        .sliceSize = SLICELEN_50K,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateBck, DIDofinalBck,
            DIUpdateBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 12,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha256MultiMulti success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_002
int CaseDigestSha384OnceOnce(void)
{
    TestVector tv = {
        .algName = {"DI_sha384"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA100K_LE1B,
        .sliceSize = SLICELEN_100K_GR200B,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIDofinalFwd, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 6,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha384OnceOnce success\n", __func__);
    return 0;
}
// Crypto_DI_Fun_004
int CaseDigestSha384OnceMulti(void)
{
    TestVector tv = {
        .algName = {"DI_sha384"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA100K_LE1B,
        .sliceSize = SLICELEN_100K_GR200B,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIDofinalFwd, DIDofinalFwd,
            DIDofinalBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 8,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha384OnceMulti success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_001
int CaseDigestSha384MultiOnce(void)
{
    TestVector tv = {
        .algName = {"DI_sha384"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA100K_GR500B,
        .sliceSize = SLICELEN_100K_GR200B,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 8,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha384MultiOnce success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_003
int CaseDigestSha384MultiMulti(void)
{
    TestVector tv = {
        .algName = {"DI_sha384"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA100K_GR500B,
        .sliceSize = SLICELEN_100K_GR200B,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateBck, DIDofinalBck,
            DIUpdateBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 12,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha384MultiMulti success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_002
int CaseDigestSha512OnceOnce(void)
{
    TestVector tv = {
        .algName = {"DI_sha512"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA250K_LE128B,
        .sliceSize = SLICELEN_250K_GR200B,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIDofinalFwd, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 6,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha512OnceOnce success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_004
int CaseDigestSha512OnceMulti(void)
{
    TestVector tv = {
        .algName = {"DI_sha512"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA250K_LE128B,
        .sliceSize = SLICELEN_250K_GR200B,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIDofinalFwd, DIDofinalFwd,
            DIDofinalBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 8,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha512OnceMulti success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_001
int CaseDigestSha512MultiOnce(void)
{
    TestVector tv = {
        .algName = {"DI_sha512"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA250K_GR200B,
        .sliceSize = SLICELEN_250K_GR200B,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 8,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha512MultiOnce success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_003
int CaseDigestSha512MultiMulti(void)
{
    TestVector tv = {
        .algName = {"DI_sha512"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA250K_GR200B,
        .sliceSize = SLICELEN_250K_GR200B,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateBck, DIDofinalBck,
            DIUpdateBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 12,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSha512MultiMulti success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_002
int CaseDigestSM3OnceOnce(void)
{
    TestVector tv = {
        .algName = {"DI_sm3"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA500K_LE1B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIDofinalFwd, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 6,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSM3OnceOnce success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_004
int CaseDigestSM3OnceMulti(void)
{
    TestVector tv = {
        .algName = {"DI_sm3"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA500K_LE1B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIDofinalFwd, DIDofinalFwd,
            DIDofinalBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 8,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSM3OnceMulti success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_001
int CaseDigestSM3MultiOnce(void)
{
    TestVector tv = {
        .algName = {"DI_sm3"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA500K_GR1B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 8,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSM3MultiOnce success\n", __func__);
    return 0;
}

// Crypto_DI_Fun_003
int CaseDigestSM3MultiMulti(void)
{
    TestVector tv = {
        .algName = {"DI_sm3"},
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = DATA500K_GR1B,
        .sliceSize = SLICELEN_500K,
        .actions = {
            IRSetUp,
            GlbAlloc,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateFwd, DIDofinalFwd,
            DIUpdateBck, DIDofinalBck,
            DIUpdateBck, DIDofinalBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 12,
        .expRet = ER_OK,
    };
    tlogi("---------------********:sliceSize:%d, dataSize:%d\n", tv.sliceSize, tv.dataSize);
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDigestSM3MultiMulti success\n", __func__);
    return 0;
}

