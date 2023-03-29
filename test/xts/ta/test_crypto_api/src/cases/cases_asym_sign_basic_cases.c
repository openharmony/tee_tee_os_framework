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

// Crypto_AsymSign_Fun_001
int CaseAsymSignRsaV15Sha384KeySize2048Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_rsa_v15_sha384"},
        .operaMaxKeySize = 2048,
        .keySize = 2048,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_3,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 48,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignRsaV15Sha384KeySize2048Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_002
int CaseAsymSignRsaV15Sha384KeySize2048Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_rsa_v15_sha384"},
        .operaMaxKeySize = 2048,
        .keySize = 2048,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_3,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 48,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignRsaV15Sha384KeySize2048Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_001
int CaseAsymSignRsaV15Sha512KeySize4096Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_rsa_v15_sha512"},
        .operaMaxKeySize = 4096,
        .keySize = 4096,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_4,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignRsaV15Sha512KeySize4096Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_002
int CaseAsymSignRsaV15Sha512KeySize4096Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_rsa_v15_sha512"},
        .operaMaxKeySize = 4096,
        .keySize = 4096,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_4,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignRsaV15Sha512KeySize4096Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_003
int CaseAsymSignRsaPssSha384KeySize2048Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_rsa_pss_SHA384"},
        .operaMaxKeySize = 2048,
        .keySize = 2048,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_3,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 48,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignRsaPssSha384KeySize2048Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_004
int CaseAsymSignRsaPssSha384KeySize2048Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_rsa_pss_SHA384"},
        .operaMaxKeySize = 2048,
        .keySize = 2048,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_3,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 48,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignRsaPssSha384KeySize2048Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_003
int CaseAsymSignRsaPssSha512KeySize4096Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_rsa_pss_SHA512"},
        .operaMaxKeySize = 4096,
        .keySize = 4096,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_4,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignRsaPssSha512KeySize4096Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_004
int CaseAsymSignRsaPssSha512KeySize4096Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_rsa_pss_SHA512"},
        .operaMaxKeySize = 4096,
        .keySize = 4096,
        .rsaGenPubExpId  = TST_RSA_KEYGEN_PUB_EXP_ID_4,
        .fwdKeyTypeName = "kt_rsa_pair",
        .bckKeyTypeName = "kt_rsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignRsaPssSha512KeySize4096Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_005
int CaseAsymSignEcdsaSha256KeySize256Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ecdsa_sha256"},
        .operaMaxKeySize = 521,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P256,
        .fwdKeyTypeName = "kt_ecdsa_pair",
        .bckKeyTypeName = "kt_ecdsa_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 32,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEcdsaSha256KeySize256Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_006
int CaseAsymSignEcdsaSha256KeySize256Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ecdsa_sha256"},
        .operaMaxKeySize = 521,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P256,
        .fwdKeyTypeName = "kt_ecdsa_pair",
        .bckKeyTypeName = "kt_ecdsa_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 32,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEcdsaSha256KeySize256Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_005
int CaseAsymSignEcdsaSha384KeySize384Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ecdsa_sha384"},
        .operaMaxKeySize = 521,
        .keySize = 384,
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P384,
        .fwdKeyTypeName = "kt_ecdsa_pair",
        .bckKeyTypeName = "kt_ecdsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 48,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEcdsaSha384KeySize384Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_006
int CaseAsymSignEcdsaSha384KeySize384Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ecdsa_sha384"},
        .operaMaxKeySize = 521,
        .keySize = 384,
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P384,
        .fwdKeyTypeName = "kt_ecdsa_pair",
        .bckKeyTypeName = "kt_ecdsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 48,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEcdsaSha384KeySize384Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_005
int CaseAsymSignEcdsaSha512KeySize521Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ecdsa_sha512"},
        .operaMaxKeySize = 521,
        .keySize = 521,
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P521,
        .fwdKeyTypeName = "kt_ecdsa_pair",
        .bckKeyTypeName = "kt_ecdsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEcdsaSha512KeySize521Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_006
int CaseAsymSignEcdsaSha512KeySize521Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ecdsa_sha512"},
        .operaMaxKeySize = 521,
        .keySize = 521,
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P521,
        .fwdKeyTypeName = "kt_ecdsa_pair",
        .bckKeyTypeName = "kt_ecdsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEcdsaSha512KeySize521Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_007
int CaseAsymSignEd25519DataSize64Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ed25519"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_25519,
        .fwdKeyTypeName = "kt_ed25519_pair",
        .bckKeyTypeName = "kt_ed25519_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEd25519DataSize64Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_008
int CaseAsymSignEd25519DataSize64Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ed25519"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_25519,
        .fwdKeyTypeName = "kt_ed25519_pair",
        .bckKeyTypeName = "kt_ed25519_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 64,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEd25519DataSize64Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_007
int CaseAsymSignEd25519DataSize470Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ed25519"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_25519,
        .fwdKeyTypeName = "kt_ed25519_pair",
        .bckKeyTypeName = "kt_ed25519_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 470,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEd25519DataSize470Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_008
int CaseAsymSignEd25519DataSize470Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ed25519"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_25519,
        .fwdKeyTypeName = "kt_ed25519_pair",
        .bckKeyTypeName = "kt_ed25519_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 470,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEd25519DataSize470Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_007
int CaseAsymSignEd25519DataSize1270Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ed25519"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_25519,
        .fwdKeyTypeName = "kt_ed25519_pair",
        .bckKeyTypeName = "kt_ed25519_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 1270,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEd25519DataSize1270Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_008
int CaseAsymSignEd25519DataSize1270Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ed25519"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_25519,
        .fwdKeyTypeName = "kt_ed25519_pair",
        .bckKeyTypeName = "kt_ed25519_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 1270,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEd25519DataSize1270Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_007
int CaseAsymSignEd25519DataSize4096Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ed25519"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_25519,
        .fwdKeyTypeName = "kt_ed25519_pair",
        .bckKeyTypeName = "kt_ed25519_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 4096,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEd25519DataSize4096Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_008
int CaseAsymSignEd25519DataSize4096Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_ed25519"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_25519,
        .fwdKeyTypeName = "kt_ed25519_pair",
        .bckKeyTypeName = "kt_ed25519_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 4096,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignEd25519DataSize4096Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_009
int CaseAsymSignSm2DsaSm3DataSize32Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_sm2_dsa_sm3"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_SM2,
        .fwdKeyTypeName = "kt_sm2_dsa_pair",
        .bckKeyTypeName = "kt_sm2_dsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 32,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignSm2DsaSm3DataSize32Once success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_010
int CaseAsymSignSm2DsaSm3DataSize32Multi(void)
{
    TestVector tv = {
        .algName = {"AS_sv_sm2_dsa_sm3"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_SM2,
        .fwdKeyTypeName = "kt_sm2_dsa_pair",
        .bckKeyTypeName = "kt_sm2_dsa_pub",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 32,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd, ASVerifyBck,
            ASSignFwd, ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignSm2DsaSm3DataSize32Multi success\n", __func__);
    return 0;
}

// Crypto_AsymSign_Fun_009
int CaseAsymSignSm2DsaSm3DataSize128Once(void)
{
    TestVector tv = {
        .algName = {"AS_sv_sm2_dsa_sm3"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .ecKeyCurve = TEE_ECC_CURVE_SM2,
        .fwdKeyTypeName = "kt_sm2_dsa_pair",
        .bckKeyTypeName = "kt_sm2_dsa_pair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 128,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            ASSignFwd,
            ASVerifyBck,
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
    tlogi("[%s]:--------------CaseAsymSignSm2DsaSm3DataSize128Once success\n", __func__);
    return 0;
}