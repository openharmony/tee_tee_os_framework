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

// Crypto_AsymEncrypt_Fun_001
int CaseAsymEncryptRsaV15KeySize512Once(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_v15"},
        .operaMaxKeySize = 512,
        .keySize = 512,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_0,
        .fwdKeyTypeName = "kt_rsa_pub",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64 - 11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd,
            ASDecryBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAsymEncryptRsaV15KeySize512Once success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_001
int CaseAsymEncryptRsaV15KeySize2048Once(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_v15"},
        .operaMaxKeySize = 2048,
        .keySize = 2048,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_2,
        .fwdKeyTypeName = "kt_rsa_pub",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 256 - 11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd,
            ASDecryBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAsymEncryptRsaV15KeySize2048Once success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_002
int CaseAsymEncryptRsaV15KeySize2048Multi(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_v15"},
        .operaMaxKeySize = 2048,
        .keySize = 2048,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_2,
        .fwdKeyTypeName = "kt_rsa_pub",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 256 - 11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            ASEncryFwd, ASDecryBck,
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
    tlogi("[%s]:--------------CaseAsymEncryptRsaV15KeySize2048Multi success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_001
int CaseAsymEncryptRsaV15KeySize4096Once(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_v15"},
        .operaMaxKeySize = 4096,
        .keySize = 4096,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_4,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 512 - 11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd,
            ASDecryBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAsymEncryptRsaV15KeySize4096Once success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_002
int CaseAsymEncryptRsaV15KeySize4096Multi(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_v15"},
        .operaMaxKeySize = 4096,
        .keySize = 4096,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_4,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 512 - 11,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            ASEncryFwd, ASDecryBck,
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
    tlogi("[%s]:--------------CaseAsymEncryptRsaV15KeySize4096Multi success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_003
int CaseAsymEncryptRsaOaepSha384KeySize2048Once(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_oaep_sha384"},
        .operaMaxKeySize = 2048,
        .keySize = 2048,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_1,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 256 - 98,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd,
            ASDecryBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAsymEncryptRsaOaepSha384KeySize2048Once success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_004
int CaseAsymEncryptRsaOaepSha384KeySize2048Multi(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_oaep_sha384"},
        .operaMaxKeySize = 2048,
        .keySize = 2048,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_1,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 256 - 98,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            ASEncryFwd, ASDecryBck,
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
    tlogi("[%s]:--------------CaseAsymEncryptRsaOaepSha384KeySize2048Multi success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_003
int CaseAsymEncryptRsaOaepSha512KeySize4096Once(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_oaep_sha512"},
        .operaMaxKeySize = 4096,
        .keySize = 4096,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_4,
        .fwdKeyTypeName = "kt_rsa_pub",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 512 - 130,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd,
            ASDecryBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAsymEncryptRsaOaepSha512KeySize4096Once success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_004
int CaseAsymEncryptRsaOaepSha512KeySize4096Multi(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_oaep_sha512"},
        .operaMaxKeySize = 4096,
        .keySize = 4096,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_4,
        .fwdKeyTypeName = "kt_rsa_pub",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 512 - 130,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            ASEncryFwd, ASDecryBck,
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
    tlogi("[%s]:--------------CaseAsymEncryptRsaOaepSha512KeySize4096Multi success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_006
int CaseAsymEncryptRsaNopadKeySize2688Once(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_nopad"},
        .operaMaxKeySize = 2688,
        .keySize = 2688,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_1,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 336,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAsymEncryptRsaNopadKeySize2688Once success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_006
int CaseAsymEncryptRsaNopadKeySize2688Multi(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_nopad"},
        .operaMaxKeySize = 2688,
        .keySize = 2688,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_1,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 336,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            ASEncryFwd, ASDecryBck,
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
    tlogi("[%s]:--------------CaseAsymEncryptRsaNopadKeySize2688Multi success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_006
int CaseAsymEncryptRsaNopadKeySize4096Once(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_nopad"},
        .operaMaxKeySize = 4096,
        .keySize = 4096,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_4,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 512,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAsymEncryptRsaNopadKeySize4096Once success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_006
int CaseAsymEncryptRsaNopadKeySize4096Multi(void)
{
    TestVector tv = {
        .algName = {"AS_ed_rsa_nopad"},
        .operaMaxKeySize = 4096,
        .keySize = 4096,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_4,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 512,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            ASEncryFwd, ASDecryBck,
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
    tlogi("[%s]:--------------CaseAsymEncryptRsaNopadKeySize4096Multi success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_007
int CaseAsymEncryptSm2PkeDataSize64Once(void)
{
    TestVector tv = {
        .algName = {"AS_ed_sm2_pke"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_sm2_pke_pub",
        .bckKeyTypeName = "kt_sm2_pke_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAsymEncryptSm2PkeDataSize64Once success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_008
int CaseAsymEncryptSm2PkeDataSize64Multi(void)
{
    TestVector tv = {
        .algName = {"AS_ed_sm2_pke"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_sm2_pke_pub",
        .bckKeyTypeName = "kt_sm2_pke_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            ASEncryFwd, ASDecryBck,
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
    tlogi("[%s]:--------------CaseAsymEncryptSm2PkeDataSize64Multi success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_007
int CaseAsymEncryptSm2PkeDataSize470Once(void)
{
    TestVector tv = {
        .algName = {"AS_ed_sm2_pke"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_sm2_pke_pair",
        .bckKeyTypeName = "kt_sm2_pke_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 470,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAsymEncryptSm2PkeDataSize470Once success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_008
int CaseAsymEncryptSm2PkeDataSize470Multi(void)
{
    TestVector tv = {
        .algName = {"AS_ed_sm2_pke"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_sm2_pke_pair",
        .bckKeyTypeName = "kt_sm2_pke_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 470,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            ASEncryFwd, ASDecryBck,
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
    tlogi("[%s]:--------------CaseAsymEncryptSm2PkeDataSize470Multi success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_007
int CaseAsymEncryptSm2PkeDataSize1024Once(void)
{
    TestVector tv = {
        .algName = {"AS_ed_sm2_pke"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_sm2_pke_pub",
        .bckKeyTypeName = "kt_sm2_pke_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 1024,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseAsymEncryptSm2PkeDataSize1024Once success\n", __func__);
    return 0;
}

// Crypto_AsymEncrypt_Fun_008
int CaseAsymEncryptSm2PkeDataSize1024Multi(void)
{
    TestVector tv = {
        .algName = {"AS_ed_sm2_pke"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_sm2_pke_pub",
        .bckKeyTypeName = "kt_sm2_pke_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 1024,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASEncryFwd, ASDecryBck,
            ASEncryFwd, ASDecryBck,
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
    tlogi("[%s]:--------------CaseAsymEncryptSm2PkeDataSize1024Multi success\n", __func__);
    return 0;
}
