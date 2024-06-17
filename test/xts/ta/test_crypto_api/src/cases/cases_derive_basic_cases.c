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

// Crypto_DR_Fun7.0.0_001
int CaseDRDHKeySize512Pram512DataSize1024(void)
{
    TestVector tv = {
        .algName = {"DR_dh"},
        .operaMaxKeySize = 512,
        .keySize = 512,
        .fwdKeyTypeName = "kt_dh_pair",
        .bckKeyTypeName = "kt_dh_pair",
        .dhGenKeySize = 512,
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 1024,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            DRDeriveFwd,
            DRDeriveBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_JF,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDRDHKeySize512Pram512DataSize1024 success\n", __func__);
    return 0;
}

// Crypto_DR_Fun7.0.0_001
int CaseDRDHKeySize1024Pram1024DataSize1024(void)
{
    TestVector tv = {
        .algName = {"DR_dh"},
        .operaMaxKeySize = 1024,
        .keySize = 1024,
        .fwdKeyTypeName = "kt_dh_pair",
        .bckKeyTypeName = "kt_dh_pair",
        .dhGenKeySize = 1024,
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 1024,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            DRDeriveFwd,
            DRDeriveBck,
            GlbFree,
            IRTearDown, },
        .actionsSize = 7,
        .expRet = ER_JF,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseDRDHKeySize1024Pram1024DataSize1024 success\n", __func__);
    return 0;
}

// Crypto_DR_Fun7.0.0_002
int CaseDREcdhNistP224DataSize14(void)
{
    TestVector tv = {
        .algName = {"DR_ecdh"},
        .operaMaxKeySize = 224,
        .keySize = 224,
        .fwdKeyTypeName = "kt_ecdh_pair",
        .bckKeyTypeName = "kt_ecdh_pair",
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P224,
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 10000,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            DRDeriveFwd,
            DRDeriveBck,
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
    tlogi("[%s]:--------------CaseDREcdhNistP224DataSize14 success\n", __func__);
    return 0;
}

// Crypto_DR_Fun7.0.0_002
int CaseDREcdhNistP256DataSize128(void)
{
    TestVector tv = {
        .algName = {"DR_ecdh"},
        .operaMaxKeySize = 521,
        .keySize = 256,
        .fwdKeyTypeName = "kt_ecdh_pair",
        .bckKeyTypeName = "kt_ecdh_pair",
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P256,
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 128,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            DRDeriveFwd,
            DRDeriveBck,
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
    tlogi("[%s]:--------------CaseDREcdhNistP256DataSize128 success\n", __func__);
    return 0;
}

// Crypto_DR_Fun7.0.0_002
int CaseDREcdhNistP384DataSize512(void)
{
    TestVector tv = {
        .algName = {"DR_ecdh"},
        .operaMaxKeySize = 521,
        .keySize = 384,
        .fwdKeyTypeName = "kt_ecdh_pair",
        .bckKeyTypeName = "kt_ecdh_pair",
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P384,
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 512,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            DRDeriveFwd,
            DRDeriveBck,
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
    tlogi("[%s]:--------------CaseDREcdhNistP384DataSize512 success\n", __func__);
    return 0;
}

// Crypto_DR_Fun7.0.0_002
int CaseDREcdhNistP521DataSize1024(void)
{
    TestVector tv = {
        .algName = {"DR_ecdh"},
        .operaMaxKeySize = 521,
        .keySize = 521,
        .fwdKeyTypeName = "kt_ecdh_pair",
        .bckKeyTypeName = "kt_ecdh_pair",
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P521,
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 1024,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            DRDeriveFwd,
            DRDeriveBck,
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
    tlogi("[%s]:--------------CaseDREcdhNistP521DataSize1024 success\n", __func__);
    return 0;
}

// Crypto_DR_Fun7.0.0_002
int CaseDREcdhNistP521DataSize4096(void)
{
    TestVector tv = {
        .algName = {"DR_ecdh"},
        .operaMaxKeySize = 521,
        .keySize = 521,
        .fwdKeyTypeName = "kt_ecdh_pair",
        .bckKeyTypeName = "kt_ecdh_pair",
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P521,
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 4096,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            DRDeriveFwd,
            DRDeriveBck,
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
    tlogi("[%s]:--------------CaseDREcdhNistP521DataSize4096 success\n", __func__);
    return 0;
}

// Crypto_DR_Fun7.0.0_002
int CaseDREcdhNistP384DataSize10000(void)
{
    TestVector tv = {
        .algName = {"DR_ecdh"},
        .operaMaxKeySize = 521,
        .keySize = 384,
        .fwdKeyTypeName = "kt_ecdh_pair",
        .bckKeyTypeName = "kt_ecdh_pair",
        .ecKeyCurve = TEE_ECC_CURVE_NIST_P384,
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 10000,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            DRDeriveFwd,
            DRDeriveBck,
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
    tlogi("[%s]:--------------CaseDREcdhNistP384DataSize10000 success\n", __func__);
    return 0;
}

// Crypto_DR_Fun7.0.0_003
int CaseDRX25519DataSize1024(void)
{
    TestVector tv = {
        .algName = {"DR_x25519"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_x25519_keypair",
        .bckKeyTypeName = "kt_x25519_keypair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 1024,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            DRDeriveFwd,
            DRDeriveBck,
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
    tlogi("[%s]:--------------CaseDRX25519DataSize1024 success\n", __func__);
    return 0;
}

// Crypto_DR_Fun7.0.0_003
int CaseDRX25519DataSize4096(void)
{
    TestVector tv = {
        .algName = {"DR_x25519"},
        .operaMaxKeySize = 256,
        .keySize = 256,
        .fwdKeyTypeName = "kt_x25519_keypair",
        .bckKeyTypeName = "kt_x25519_keypair",
        .fwdEngine = FWDENGINE,
        .bckEngine = BCKENGINE,
        .dataSize = 4096,
        .actions = {
            IRSetUp,
            GlbAlloc, GlbS1S2,
            DRDeriveFwd,
            DRDeriveBck,
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
    tlogi("[%s]:--------------CaseDRX25519DataSize4096 success\n", __func__);
    return 0;
}
