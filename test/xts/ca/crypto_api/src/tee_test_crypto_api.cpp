/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <common_test.h>

using namespace testing::ext;
/**
 * @testcase.name      : CaseDigestSha256OnceOnce
 * @testcase.desc      : run case CaseDigestSha256OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha256OnceOnce);

/**
 * @testcase.name      : CaseDigestSha256OnceMulti
 * @testcase.desc      : run case CaseDigestSha256OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha256OnceMulti);

/**
 * @testcase.name      : CaseDigestSha256MultiOnce
 * @testcase.desc      : run case CaseDigestSha256MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha256MultiOnce);

/**
 * @testcase.name      : CaseDigestSha256MultiMulti
 * @testcase.desc      : run case CaseDigestSha256MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha256MultiMulti);

/**
 * @testcase.name      : CaseDigestSha384OnceOnce
 * @testcase.desc      : run case CaseDigestSha384OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha384OnceOnce);

/**
 * @testcase.name      : CaseDigestSha384OnceMulti
 * @testcase.desc      : run case CaseDigestSha384OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha384OnceMulti);

/**
 * @testcase.name      : CaseDigestSha384MultiOnce
 * @testcase.desc      : run case CaseDigestSha384MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha384MultiOnce);

/**
 * @testcase.name      : CaseDigestSha384MultiMulti
 * @testcase.desc      : run case CaseDigestSha384MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha384MultiMulti);

/**
 * @testcase.name      : CaseDigestSha512OnceOnce
 * @testcase.desc      : run case CaseDigestSha512OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha512OnceOnce);

/**
 * @testcase.name      : CaseDigestSha512OnceMulti
 * @testcase.desc      : run case CaseDigestSha512OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha512OnceMulti);

/**
 * @testcase.name      : CaseDigestSha512MultiOnce
 * @testcase.desc      : run case CaseDigestSha512MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha512MultiOnce);

/**
 * @testcase.name      : CaseDigestSha512MultiMulti
 * @testcase.desc      : run case CaseDigestSha512MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDigestSha512MultiMulti);

/**
 * @testcase.name      : CaseDigestSM3OnceOnce
 * @testcase.desc      : run case CaseDigestSM3OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseDigestSM3OnceOnce);

/**
 * @testcase.name      : CaseDigestSM3OnceMulti
 * @testcase.desc      : run case CaseDigestSM3OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseDigestSM3OnceMulti);

/**
 * @testcase.name      : CaseDigestSM3MultiOnce
 * @testcase.desc      : run case CaseDigestSM3MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseDigestSM3MultiOnce);

/**
 * @testcase.name      : CaseDigestSM3MultiMulti
 * @testcase.desc      : run case CaseDigestSM3MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseDigestSM3MultiMulti);

/**
 * @testcase.name      : CaseDREcdhNistP224DataSize14
 * @testcase.desc      : run case CaseDREcdhNistP224DataSize14
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseDREcdhNistP224DataSize14);

/**
 * @testcase.name      : CaseDREcdhNistP256DataSize128
 * @testcase.desc      : run case CaseDREcdhNistP256DataSize128
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDREcdhNistP256DataSize128);

/**
 * @testcase.name      : CaseDREcdhNistP384DataSize512
 * @testcase.desc      : run case CaseDREcdhNistP384DataSize512
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDREcdhNistP384DataSize512);

/**
 * @testcase.name      : CaseDREcdhNistP521DataSize1024
 * @testcase.desc      : run case CaseDREcdhNistP521DataSize1024
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDREcdhNistP521DataSize1024);

/**
 * @testcase.name      : CaseDREcdhNistP521DataSize4096
 * @testcase.desc      : run case CaseDREcdhNistP521DataSize4096
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDREcdhNistP521DataSize4096);

/**
 * @testcase.name      : CaseDREcdhNistP384DataSize10000
 * @testcase.desc      : run case CaseDREcdhNistP384DataSize10000
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDREcdhNistP384DataSize10000);

/**
 * @testcase.name      : CaseDRDHKeySize512Pram512DataSize1024
 * @testcase.desc      : run case CaseDRDHKeySize512Pram512DataSize1024
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDRDHKeySize512Pram512DataSize1024);

/**
 * @testcase.name      : CaseDRDHKeySize1024Pram1024DataSize1024
 * @testcase.desc      : run case CaseDRDHKeySize1024Pram1024DataSize1024
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDRDHKeySize1024Pram1024DataSize1024);

/**
 * @testcase.name      : CaseDRX25519DataSize1024
 * @testcase.desc      : run case CaseDRX25519DataSize1024
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDRX25519DataSize1024);

/**
 * @testcase.name      : CaseDRX25519DataSize4096
 * @testcase.desc      : run case CaseDRX25519DataSize4096
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseDRX25519DataSize4096);

/**
 * @testcase.name      : CaseSymEncryptAesEcbNopadKeySize128OnceOnce
 * @testcase.desc      : run case CaseSymEncryptAesEcbNopadKeySize128OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptAesEcbNopadKeySize128OnceOnce);

/**
 * @testcase.name      : CaseSymEncryptAesEcbNopadKeySize128OnceMulti
 * @testcase.desc      : run case CaseSymEncryptAesEcbNopadKeySize128OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptAesEcbNopadKeySize128OnceMulti);

/**
 * @testcase.name      : CaseSymEncryptAesEcbNopadKeySize128MultiOnce
 * @testcase.desc      : run case CaseSymEncryptAesEcbNopadKeySize128MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptAesEcbNopadKeySize128MultiOnce);

/**
 * @testcase.name      : CaseSymEncryptAesEcbNopadKeySize128MultiMulti
 * @testcase.desc      : run case CaseSymEncryptAesEcbNopadKeySize128MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptAesEcbNopadKeySize128MultiMulti)
;

/**
 * @testcase.name      : CaseSymEncryptAesCbcNopadKeySize192OnceOnce
 * @testcase.desc      : run case CaseSymEncryptAesCbcNopadKeySize192OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCbcNopadKeySize192OnceOnce);

/**
 * @testcase.name      : CaseSymEncryptAesCbcNopadKeySize192OnceMulti
 * @testcase.desc      : run case CaseSymEncryptAesCbcNopadKeySize192OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCbcNopadKeySize192OnceMulti);

/**
 * @testcase.name      : CaseSymEncryptAesCbcNopadKeySize192MultiOnce
 * @testcase.desc      : run case CaseSymEncryptAesCbcNopadKeySize192MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCbcNopadKeySize192MultiOnce);

/**
 * @testcase.name      : CaseSymEncryptAesCbcNopadKeySize192MultiMulti
 * @testcase.desc      : run case CaseSymEncryptAesCbcNopadKeySize192MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCbcNopadKeySize192MultiMulti);

/**
 * @testcase.name      : CaseSymEncryptAesCtrKeySize128OnceOnce
 * @testcase.desc      : run case CaseSymEncryptAesCtrKeySize128OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCtrKeySize128OnceOnce);

/**
 * @testcase.name      : CaseSymEncryptAesCtrKeySize128OnceMulti
 * @testcase.desc      : run case CaseSymEncryptAesCtrKeySize128OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCtrKeySize128OnceMulti);

/**
 * @testcase.name      : CaseSymEncryptAesCtrKeySize128MultiOnce
 * @testcase.desc      : run case CaseSymEncryptAesCtrKeySize128MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCtrKeySize128MultiOnce);

/**
 * @testcase.name      : CaseSymEncryptAesCtrKeySize128MultiMulti
 * @testcase.desc      : run case CaseSymEncryptAesCtrKeySize128MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCtrKeySize128MultiMulti);

/**
 * @testcase.name      : CaseSymEncryptAesXtsKeySize256OnceOnce
 * @testcase.desc      : run case CaseSymEncryptAesXtsKeySize256OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesXtsKeySize256OnceOnce);

/**
 * @testcase.name      : CaseSymEncryptAesXtsKeySize256OnceMulti
 * @testcase.desc      : run case CaseSymEncryptAesXtsKeySize256OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesXtsKeySize256OnceMulti);

/**
 * @testcase.name      : CaseSymEncryptAesXtsKeySize256MultiOnce
 * @testcase.desc      : run case CaseSymEncryptAesXtsKeySize256MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesXtsKeySize256MultiOnce);

/**
 * @testcase.name      : CaseSymEncryptAesXtsKeySize256MultiMulti
 * @testcase.desc      : run case CaseSymEncryptAesXtsKeySize256MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesXtsKeySize256MultiMulti);

/**
 * @testcase.name      : CaseSymEncryptAesCbcPkcs5KeySize256OnceOnce
 * @testcase.desc      : run case CaseSymEncryptAesCbcPkcs5KeySize256OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCbcPkcs5KeySize256OnceOnce);

/**
 * @testcase.name      : CaseSymEncryptAesCbcPkcs5KeySize256OnceMulti
 * @testcase.desc      : run case CaseSymEncryptAesCbcPkcs5KeySize256OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCbcPkcs5KeySize256OnceMulti);

/**
 * @testcase.name      : CaseSymEncryptAesCbcPkcs5KeySize256MultiOnce
 * @testcase.desc      : run case CaseSymEncryptAesCbcPkcs5KeySize256MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCbcPkcs5KeySize256MultiOnce);

/**
 * @testcase.name      : CaseSymEncryptAesCbcPkcs5KeySize256MultiMulti
 * @testcase.desc      : run case CaseSymEncryptAesCbcPkcs5KeySize256MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseSymEncryptAesCbcPkcs5KeySize256MultiMulti);

/**
 * @testcase.name      : CaseSymEncryptSm4CbcNopadKeySize128OnceOnce
 * @testcase.desc      : run case CaseSymEncryptSm4CbcNopadKeySize128OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CbcNopadKeySize128OnceOnce);

/**
 * @testcase.name      : CaseSymEncryptSm4CbcNopadKeySize128OnceMulti
 * @testcase.desc      : run case CaseSymEncryptSm4CbcNopadKeySize128OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CbcNopadKeySize128OnceMulti);

/**
 * @testcase.name      : CaseSymEncryptSm4CbcNopadKeySize128MultiOnce
 * @testcase.desc      : run case CaseSymEncryptSm4CbcNopadKeySize128MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CbcNopadKeySize128MultiOnce);

/**
 * @testcase.name      : CaseSymEncryptSm4CbcNopadKeySize128MultiMulti
 * @testcase.desc      : run case CaseSymEncryptSm4CbcNopadKeySize128MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CbcNopadKeySize128MultiMulti);

/**
 * @testcase.name      : CaseSymEncryptSm4CtrKeySize128OnceOnce
 * @testcase.desc      : run case CaseSymEncryptSm4CtrKeySize128OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CtrKeySize128OnceOnce);

/**
 * @testcase.name      : CaseSymEncryptSm4CtrKeySize128OnceMulti
 * @testcase.desc      : run case CaseSymEncryptSm4CtrKeySize128OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CtrKeySize128OnceMulti);

/**
 * @testcase.name      : CaseSymEncryptSm4CtrKeySize128MultiOnce
 * @testcase.desc      : run case CaseSymEncryptSm4CtrKeySize128MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CtrKeySize128MultiOnce);

/**
 * @testcase.name      : CaseSymEncryptSm4CtrKeySize128MultiMulti
 * @testcase.desc      : run case CaseSymEncryptSm4CtrKeySize128MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CtrKeySize128MultiMulti);

/**
 * @testcase.name      : CaseSymEncryptSm4Cfb128KeySize128OnceOnce
 * @testcase.desc      : run case CaseSymEncryptSm4Cfb128KeySize128OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4Cfb128KeySize128OnceOnce);

/**
 * @testcase.name      : CaseSymEncryptSm4Cfb128KeySize128OnceMulti
 * @testcase.desc      : run case CaseSymEncryptSm4Cfb128KeySize128OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4Cfb128KeySize128OnceMulti);

/**
 * @testcase.name      : CaseSymEncryptSm4Cfb128KeySize128MultiOnce
 * @testcase.desc      : run case CaseSymEncryptSm4Cfb128KeySize128MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4Cfb128KeySize128MultiOnce);

/**
 * @testcase.name      : CaseSymEncryptSm4Cfb128KeySize128MultiMulti
 * @testcase.desc      : run case CaseSymEncryptSm4Cfb128KeySize128MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4Cfb128KeySize128MultiMulti);

/**
 * @testcase.name      : CaseSymEncryptSm4CbcPkcs7KeySize128OnceOnce
 * @testcase.desc      : run case CaseSymEncryptSm4CbcPkcs7KeySize128OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CbcPkcs7KeySize128OnceOnce);

/**
 * @testcase.name      : CaseSymEncryptSm4CbcPkcs7KeySize128OnceMulti
 * @testcase.desc      : run case CaseSymEncryptSm4CbcPkcs7KeySize128OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CbcPkcs7KeySize128OnceMulti);

/**
 * @testcase.name      : CaseSymEncryptSm4CbcPkcs7KeySize128MultiOnce
 * @testcase.desc      : run case CaseSymEncryptSm4CbcPkcs7KeySize128MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CbcPkcs7KeySize128MultiOnce);

/**
 * @testcase.name      : CaseSymEncryptSm4CbcPkcs7KeySize128MultiMulti
 * @testcase.desc      : run case CaseSymEncryptSm4CbcPkcs7KeySize128MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseSymEncryptSm4CbcPkcs7KeySize128MultiMulti);

/**
 * @testcase.name      : CaseAEAesCcmK128N7T32Aad32MultiOnce
 * @testcase.desc      : run case CaseAEAesCcmK128N7T32Aad32MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK128N7T32Aad32MultiOnce);

/**
 * @testcase.name      : CaseAEAesCcmK128N7T32Aad32MultiMulti
 * @testcase.desc      : run case CaseAEAesCcmK128N7T32Aad32MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK128N7T32Aad32MultiMulti);

/**
 * @testcase.name      : CaseAEAesCcmK128N7T32Aad32update0Multi
 * @testcase.desc      : run case CaseAEAesCcmK128N7T32Aad32update0Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK128N7T32Aad32update0Multi);

/**
 * @testcase.name      : CaseAEAesCcmK128N7T32Aad32OnceOnce
 * @testcase.desc      : run case CaseAEAesCcmK128N7T32Aad32OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK128N7T32Aad32OnceOnce);

/**
 * @testcase.name      : CaseAEAesCcmK128N7T32Aad32OnceMulti
 * @testcase.desc      : run case CaseAEAesCcmK128N7T32Aad32OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK128N7T32Aad32OnceMulti);

/**
 * @testcase.name      : CaseAEAesCcmK192N8T48Aad288MultiOnce
 * @testcase.desc      : run case CaseAEAesCcmK192N8T48Aad288MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK192N8T48Aad288MultiOnce);

/**
 * @testcase.name      : CaseAEAesCcmK192N8T48Aad288MultiMulti
 * @testcase.desc      : run case CaseAEAesCcmK192N8T48Aad288MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK192N8T48Aad288MultiMulti);

/**
 * @testcase.name      : CaseAEAesCcmK192N8T48Aad288OnceOnce
 * @testcase.desc      : run case CaseAEAesCcmK192N8T48Aad288OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK192N8T48Aad288OnceOnce);

/**
 * @testcase.name      : CaseAEAesCcmK192N8T48Aad288OnceMulti
 * @testcase.desc      : run case CaseAEAesCcmK192N8T48Aad288OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK192N8T48Aad288OnceMulti);

/**
 * @testcase.name      : CaseAEAesCcmK256N9T64Aad512MultiOnce
 * @testcase.desc      : run case CaseAEAesCcmK256N9T64Aad512MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK256N9T64Aad512MultiOnce);

/**
 * @testcase.name      : CaseAEAesCcmK256N9T64Aad512MultiMulti
 * @testcase.desc      : run case CaseAEAesCcmK256N9T64Aad512MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK256N9T64Aad512MultiMulti);

/**
 * @testcase.name      : CaseAEAesCcmK256N13T128Aad512OnceOnce
 * @testcase.desc      : run case CaseAEAesCcmK256N13T128Aad512OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK256N13T128Aad512OnceOnce);

/**
 * @testcase.name      : CaseAEAesCcmK256N13T128Aad512OnceMulti
 * @testcase.desc      : run case CaseAEAesCcmK256N13T128Aad512OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK256N13T128Aad512OnceMulti);

/**
 * @testcase.name      : CaseAEAesCcmK128N10T80Aad4MMultiOnce
 * @testcase.desc      : run case CaseAEAesCcmK128N10T80Aad4MMultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK128N10T80Aad4MMultiOnce);

/**
 * @testcase.name      : CaseAEAesCcmK128N10T80Aad4MMultiMulti
 * @testcase.desc      : run case CaseAEAesCcmK128N10T80Aad4MMultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK128N10T80Aad4MMultiMulti);

/**
 * @testcase.name      : CaseAEAesCcmK192N11T96Aad32MultiOnce
 * @testcase.desc      : run case CaseAEAesCcmK192N11T96Aad32MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK192N11T96Aad32MultiOnce);

/**
 * @testcase.name      : CaseAEAesCcmK192N11T96Aad32MultiMulti
 * @testcase.desc      : run case CaseAEAesCcmK192N11T96Aad32MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK192N11T96Aad32MultiMulti);

/**
 * @testcase.name      : CaseAEAesCcmK256N12T112Aad288MultiOnce
 * @testcase.desc      : run case CaseAEAesCcmK256N12T112Aad288MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK256N12T112Aad288MultiOnce);

/**
 * @testcase.name      : CaseAEAesCcmK256N12T112Aad288MultiMulti
 * @testcase.desc      : run case CaseAEAesCcmK256N12T112Aad288MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK256N12T112Aad288MultiMulti);

/**
 * @testcase.name      : CaseAEAesCcmK128N13T128Aad512MultiOnce
 * @testcase.desc      : run case CaseAEAesCcmK128N13T128Aad512MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK128N13T128Aad512MultiOnce);

/**
 * @testcase.name      : CaseAEAesCcmK128N13T128Aad512MultiMulti
 * @testcase.desc      : run case CaseAEAesCcmK128N13T128Aad512MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK128N13T128Aad512MultiMulti);

/**
 * @testcase.name      : CaseAEAesCcmK128N7T32Aad512EncryptOnlyTAG
 * @testcase.desc      : run case CaseAEAesCcmK128N7T32Aad512EncryptOnlyTAG
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK128N7T32Aad512EncryptOnlyTAG);

/**
 * @testcase.name      : CaseAEAesCcmK192N8T64NoAadOnce
 * @testcase.desc      : run case CaseAEAesCcmK192N8T64NoAadOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK192N8T64NoAadOnce);

/**
 * @testcase.name      : CaseAEAesCcmK192N8T64NoAadMulti
 * @testcase.desc      : run case CaseAEAesCcmK192N8T64NoAadMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK192N8T64NoAadMulti);

/**
 * @testcase.name      : CaseAEAesCcmK256N9T64Aad512DecryptOnlyTAG
 * @testcase.desc      : run case CaseAEAesCcmK256N9T64Aad512DecryptOnlyTAG
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesCcmK256N9T64Aad512DecryptOnlyTAG);

/**
 * @testcase.name      : CaseAEAesGcmK128N7T96Aad32MultiOnce
 * @testcase.desc      : run case CaseAEAesGcmK128N7T96Aad32MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK128N7T96Aad32MultiOnce);

/**
 * @testcase.name      : CaseAEAesGcmK128N7T96Aad32MultiMulti
 * @testcase.desc      : run case CaseAEAesGcmK128N7T96Aad32MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK128N7T96Aad32MultiMulti);

/**
 * @testcase.name      : CaseAEAesGcmK128N7T96Aad32update0Multi
 * @testcase.desc      : run case CaseAEAesGcmK128N7T96Aad32update0Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK128N7T96Aad32update0Multi);

/**
 * @testcase.name      : CaseAEAesGcmK128N7T96Aad32OnceOnce
 * @testcase.desc      : run case CaseAEAesGcmK128N7T96Aad32OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK128N7T96Aad32OnceOnce);

/**
 * @testcase.name      : CaseAEAesGcmK128N7T96Aad32OnceMulti
 * @testcase.desc      : run case CaseAEAesGcmK128N7T96Aad32OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK128N7T96Aad32OnceMulti);

/**
 * @testcase.name      : CaseAEAesGcmK192N12T104Aad288MultiOnce
 * @testcase.desc      : run case CaseAEAesGcmK192N12T104Aad288MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK192N12T104Aad288MultiOnce);

/**
 * @testcase.name      : CaseAEAesGcmK192N12T104Aad288MultiMulti
 * @testcase.desc      : run case CaseAEAesGcmK192N12T104Aad288MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK192N12T104Aad288MultiMulti);

/**
 * @testcase.name      : CaseAEAesGcmK192N12T104Aad288OnceOnce
 * @testcase.desc      : run case CaseAEAesGcmK192N12T104Aad288OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK192N12T104Aad288OnceOnce);

/**
 * @testcase.name      : CaseAEAesGcmK192N12T104Aad288OnceMulti
 * @testcase.desc      : run case CaseAEAesGcmK192N12T104Aad288OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK192N12T104Aad288OnceMulti);

/**
 * @testcase.name      : CaseAEAesGcmK256N7T112Aad512MultiOnce
 * @testcase.desc      : run case CaseAEAesGcmK256N7T112Aad512MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK256N7T112Aad512MultiOnce);

/**
 * @testcase.name      : CaseAEAesGcmK256N7T112Aad512MultiMulti
 * @testcase.desc      : run case CaseAEAesGcmK256N7T112Aad512MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK256N7T112Aad512MultiMulti);

/**
 * @testcase.name      : CaseAEAesGcmK256N7T128Aad512OnceOnce
 * @testcase.desc      : run case CaseAEAesGcmK256N7T128Aad512OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK256N7T128Aad512OnceOnce);

/**
 * @testcase.name      : CaseAEAesGcmK256N7T128Aad512OnceMulti
 * @testcase.desc      : run case CaseAEAesGcmK256N7T128Aad512OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK256N7T128Aad512OnceMulti);

/**
 * @testcase.name      : CaseAEAesGcmK128N12T120Aad4MMultiOnce
 * @testcase.desc      : run case CaseAEAesGcmK128N12T120Aad4MMultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK128N12T120Aad4MMultiOnce);

/**
 * @testcase.name      : CaseAEAesGcmK128N12T120Aad4MMultiMulti
 * @testcase.desc      : run case CaseAEAesGcmK128N12T120Aad4MMultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK128N12T120Aad4MMultiMulti);

/**
 * @testcase.name      : CaseAEAesGcmK192N7T128Aad32MultiOnce
 * @testcase.desc      : run case CaseAEAesGcmK192N7T128Aad32MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK192N7T128Aad32MultiOnce);

/**
 * @testcase.name      : CaseAEAesGcmK192N7T128Aad32MultiMulti
 * @testcase.desc      : run case CaseAEAesGcmK192N7T128Aad32MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK192N7T128Aad32MultiMulti);

/**
 * @testcase.name      : CaseAEAesGcmK256N7T112Aad512DecryptOnlyTAG
 * @testcase.desc      : run case CaseAEAesGcmK256N7T112Aad512DecryptOnlyTAG
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK256N7T112Aad512DecryptOnlyTAG);

/**
 * @testcase.name      : CaseAEAesGcmK192N12T96NoAadOnce
 * @testcase.desc      : run case CaseAEAesGcmK192N12T96NoAadOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK192N12T96NoAadOnce);

/**
 * @testcase.name      : CaseAEAesGcmK192N12T96NoAadMulti
 * @testcase.desc      : run case CaseAEAesGcmK192N12T96NoAadMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK192N12T96NoAadMulti);

/**
 * @testcase.name      : CaseAEAesGcmK128N7T104Aad512EncryptOnlyTAG
 * @testcase.desc      : run case CaseAEAesGcmK128N7T104Aad512EncryptOnlyTAG
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAEAesGcmK128N7T104Aad512EncryptOnlyTAG);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T96Aad32MultiOnce
 * @testcase.desc      : run case CaseAESM4GcmK128N7T96Aad32MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T96Aad32MultiOnce);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T96Aad32MultiMulti
 * @testcase.desc      : run case CaseAESM4GcmK128N7T96Aad32MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T96Aad32MultiMulti);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T96Aad32OnceOnce
 * @testcase.desc      : run case CaseAESM4GcmK128N7T96Aad32OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T96Aad32OnceOnce);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T96Aad32OnceMulti
 * @testcase.desc      : run case CaseAESM4GcmK128N7T96Aad32OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T96Aad32OnceMulti);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T96Aad32update0Multi
 * @testcase.desc      : run case CaseAESM4GcmK128N7T96Aad32update0Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T96Aad32update0Multi);

/**
 * @testcase.name      : CaseAESM4GcmK128N12T104Aad288MultiOnce
 * @testcase.desc      : run case CaseAESM4GcmK128N12T104Aad288MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N12T104Aad288MultiOnce);

/**
 * @testcase.name      : CaseAESM4GcmK128N12T104Aad288MultiMulti
 * @testcase.desc      : run case CaseAESM4GcmK128N12T104Aad288MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N12T104Aad288MultiMulti);

/**
 * @testcase.name      : CaseAESM4GcmK128N12T104Aad288OnceOnce
 * @testcase.desc      : run case CaseAESM4GcmK128N12T104Aad288OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N12T104Aad288OnceOnce);

/**
 * @testcase.name      : CaseAESM4GcmK128N12T104Aad288OnceMulti
 * @testcase.desc      : run case CaseAESM4GcmK128N12T104Aad288OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N12T104Aad288OnceMulti);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T112Aad512MultiOnce
 * @testcase.desc      : run case CaseAESM4GcmK128N7T112Aad512MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T112Aad512MultiOnce);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T112Aad512MultiMulti
 * @testcase.desc      : run case CaseAESM4GcmK128N7T112Aad512MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T112Aad512MultiMulti);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T128Aad512OnceOnce
 * @testcase.desc      : run case CaseAESM4GcmK128N7T128Aad512OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T128Aad512OnceOnce);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T128Aad512OnceMulti
 * @testcase.desc      : run case CaseAESM4GcmK128N7T128Aad512OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T128Aad512OnceMulti);

/**
 * @testcase.name      : CaseAESM4GcmK128N12T120Aad4MMultiOnce
 * @testcase.desc      : run case CaseAESM4GcmK128N12T120Aad4MMultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N12T120Aad4MMultiOnce);

/**
 * @testcase.name      : CaseAESM4GcmK128N12T120Aad4MMultiMulti
 * @testcase.desc      : run case CaseAESM4GcmK128N12T120Aad4MMultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N12T120Aad4MMultiMulti);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T128Aad32MultiOnce
 * @testcase.desc      : run case CaseAESM4GcmK128N7T128Aad32MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T128Aad32MultiOnce);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T128Aad32MultiMulti
 * @testcase.desc      : run case CaseAESM4GcmK128N7T128Aad32MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T128Aad32MultiMulti);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T112Aad512DecryptOnlyTAG
 * @testcase.desc      : run case CaseAESM4GcmK128N7T112Aad512DecryptOnlyTAG
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T112Aad512DecryptOnlyTAG);

/**
 * @testcase.name      : CaseAESM4GcmK128N12T96NoAadOnce
 * @testcase.desc      : run case CaseAESM4GcmK128N12T96NoAadOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N12T96NoAadOnce);

/**
 * @testcase.name      : CaseAESM4GcmK128N12T96NoAadMulti
 * @testcase.desc      : run case CaseAESM4GcmK128N12T96NoAadMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N12T96NoAadMulti);

/**
 * @testcase.name      : CaseAESM4GcmK128N7T104Aad512EncryptOnlyTAG
 * @testcase.desc      : run case CaseAESM4GcmK128N7T104Aad512EncryptOnlyTAG
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAESM4GcmK128N7T104Aad512EncryptOnlyTAG);

/**
 * @testcase.name      : CaseHmacSha256KeySize64OnceOnce
 * @testcase.desc      : run case CaseHmacSha256KeySize64OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha256KeySize64OnceOnce);

/**
 * @testcase.name      : CaseHmacSha256KeySize64OnceMulti
 * @testcase.desc      : run case CaseHmacSha256KeySize64OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha256KeySize64OnceMulti);

/**
 * @testcase.name      : CaseHmacSha256KeySize64MultiOnce
 * @testcase.desc      : run case CaseHmacSha256KeySize64MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha256KeySize64MultiOnce);

/**
 * @testcase.name      : CaseHmacSha256KeySize64MultiMulti
 * @testcase.desc      : run case CaseHmacSha256KeySize64MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha256KeySize64MultiMulti);

/**
 * @testcase.name      : CaseHmacSha384KeySize1024OnceOnce
 * @testcase.desc      : run case CaseHmacSha384KeySize1024OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha384KeySize1024OnceOnce);

/**
 * @testcase.name      : CaseHmacSha384KeySize1024OnceMulti
 * @testcase.desc      : run case CaseHmacSha384KeySize1024OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha384KeySize1024OnceMulti);

/**
 * @testcase.name      : CaseHmacSha384KeySize1024MultiOnce
 * @testcase.desc      : run case CaseHmacSha384KeySize1024MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha384KeySize1024MultiOnce);

/**
 * @testcase.name      : CaseHmacSha384KeySize1024MultiMulti
 * @testcase.desc      : run case CaseHmacSha384KeySize1024MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha384KeySize1024MultiMulti);

/**
 * @testcase.name      : CaseHmacSha512KeySize256OnceOnce
 * @testcase.desc      : run case CaseHmacSha512KeySize256OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha512KeySize256OnceOnce);

/**
 * @testcase.name      : CaseHmacSha512KeySize256OnceMulti
 * @testcase.desc      : run case CaseHmacSha512KeySize256OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha512KeySize256OnceMulti);

/**
 * @testcase.name      : CaseHmacSha512KeySize256MultiOnce
 * @testcase.desc      : run case CaseHmacSha512KeySize256MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha512KeySize256MultiOnce);

/**
 * @testcase.name      : CaseHmacSha512KeySize256MultiMulti
 * @testcase.desc      : run case CaseHmacSha512KeySize256MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha512KeySize256MultiMulti);

/**
 * @testcase.name      : CaseHmacSM3KeySize512OnceOnce
 * @testcase.desc      : run case CaseHmacSM3KeySize512OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseHmacSM3KeySize512OnceOnce);

/**
 * @testcase.name      : CaseHmacSM3KeySize512OnceMulti
 * @testcase.desc      : run case CaseHmacSM3KeySize512OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseHmacSM3KeySize512OnceMulti);

/**
 * @testcase.name      : CaseHmacSM3KeySize512MultiOnce
 * @testcase.desc      : run case CaseHmacSM3KeySize512MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseHmacSM3KeySize512MultiOnce);

/**
 * @testcase.name      : CaseHmacSM3KeySize512MultiMulti
 * @testcase.desc      : run case CaseHmacSM3KeySize512MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseHmacSM3KeySize512MultiMulti);

/**
 * @testcase.name      : CaseHmacSha256KeySize8192OnceOnce
 * @testcase.desc      : run case CaseHmacSha256KeySize8192OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha256KeySize8192OnceOnce);

/**
 * @testcase.name      : CaseHmacSha256KeySize8192OnceMulti
 * @testcase.desc      : run case CaseHmacSha256KeySize8192OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha256KeySize8192OnceMulti);

/**
 * @testcase.name      : CaseHmacSha256KeySize8192MultiOnce
 * @testcase.desc      : run case CaseHmacSha256KeySize8192MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha256KeySize8192MultiOnce);

/**
 * @testcase.name      : CaseHmacSha256KeySize8192MultiMulti
 * @testcase.desc      : run case CaseHmacSha256KeySize8192MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseHmacSha256KeySize8192MultiMulti);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize128OnceOnce
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize128OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize128OnceOnce);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize128OnceMulti
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize128OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize128OnceMulti);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize128MultiOnce
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize128MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize128MultiOnce);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize128MultiMulti
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize128MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize128MultiMulti);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize192OnceOnce
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize192OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize192OnceOnce);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize192OnceMulti
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize192OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize192OnceMulti);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize192MultiOnce
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize192MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize192MultiOnce);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize192MultiMulti
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize192MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize192MultiMulti);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize256OnceOnce
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize256OnceOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize256OnceOnce);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize256OnceMulti
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize256OnceMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize256OnceMulti);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize256MultiOnce
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize256MultiOnce
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize256MultiOnce);

/**
 * @testcase.name      : CaseCmacAesCbcNopadKeySize256MultiMulti
 * @testcase.desc      : run case CaseCmacAesCbcNopadKeySize256MultiMulti
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseCmacAesCbcNopadKeySize256MultiMulti);

/**
 * @testcase.name      : CaseAsymEncryptRsaV15KeySize512Once
 * @testcase.desc      : run case CaseAsymEncryptRsaV15KeySize512Once
 * @testcase.expect    : return is not TEEC_SUCCESS
 */
// CRYPTO_TEST_NE(CaseAsymEncryptRsaV15KeySize512Once);

/**
 * @testcase.name      : CaseAsymEncryptRsaV15KeySize2048Once
 * @testcase.desc      : run case CaseAsymEncryptRsaV15KeySize2048Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptRsaV15KeySize2048Once);

/**
 * @testcase.name      : CaseAsymEncryptRsaV15KeySize2048Multi
 * @testcase.desc      : run case CaseAsymEncryptRsaV15KeySize2048Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptRsaV15KeySize2048Multi);

/**
 * @testcase.name      : CaseAsymEncryptRsaV15KeySize4096Once
 * @testcase.desc      : run case CaseAsymEncryptRsaV15KeySize4096Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymEncryptRsaV15KeySize4096Once);

/**
 * @testcase.name      : CaseAsymEncryptRsaV15KeySize4096Multi
 * @testcase.desc      : run case CaseAsymEncryptRsaV15KeySize4096Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymEncryptRsaV15KeySize4096Multi);

/**
 * @testcase.name      : CaseAsymEncryptRsaOaepSha384KeySize2048Once
 * @testcase.desc      : run case CaseAsymEncryptRsaOaepSha384KeySize2048Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptRsaOaepSha384KeySize2048Once);

/**
 * @testcase.name      : CaseAsymEncryptRsaOaepSha384KeySize2048Multi
 * @testcase.desc      : run case CaseAsymEncryptRsaOaepSha384KeySize2048Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptRsaOaepSha384KeySize2048Multi);

/**
 * @testcase.name      : CaseAsymEncryptRsaOaepSha512KeySize4096Once
 * @testcase.desc      : run case CaseAsymEncryptRsaOaepSha512KeySize4096Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymEncryptRsaOaepSha512KeySize4096Once);

/**
 * @testcase.name      : CaseAsymEncryptRsaOaepSha512KeySize4096Multi
 * @testcase.desc      : run case CaseAsymEncryptRsaOaepSha512KeySize4096Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymEncryptRsaOaepSha512KeySize4096Multi);

/**
 * @testcase.name      : CaseAsymEncryptRsaNopadKeySize2688Once
 * @testcase.desc      : run case CaseAsymEncryptRsaNopadKeySize2688Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptRsaNopadKeySize2688Once);

/**
 * @testcase.name      : CaseAsymEncryptRsaNopadKeySize2688Multi
 * @testcase.desc      : run case CaseAsymEncryptRsaNopadKeySize2688Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptRsaNopadKeySize2688Multi);

/**
 * @testcase.name      : CaseAsymEncryptRsaNopadKeySize4096Once
 * @testcase.desc      : run case CaseAsymEncryptRsaNopadKeySize4096Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymEncryptRsaNopadKeySize4096Once);

/**
 * @testcase.name      : CaseAsymEncryptRsaNopadKeySize4096Multi
 * @testcase.desc      : run case CaseAsymEncryptRsaNopadKeySize4096Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymEncryptRsaNopadKeySize4096Multi);

/**
 * @testcase.name      : CaseAsymEncryptSm2PkeDataSize64Once
 * @testcase.desc      : run case CaseAsymEncryptSm2PkeDataSize64Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptSm2PkeDataSize64Once);

/**
 * @testcase.name      : CaseAsymEncryptSm2PkeDataSize64Multi
 * @testcase.desc      : run case CaseAsymEncryptSm2PkeDataSize64Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptSm2PkeDataSize64Multi);

/**
 * @testcase.name      : CaseAsymEncryptSm2PkeDataSize470Once
 * @testcase.desc      : run case CaseAsymEncryptSm2PkeDataSize470Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptSm2PkeDataSize470Once);

/**
 * @testcase.name      : CaseAsymEncryptSm2PkeDataSize470Multi
 * @testcase.desc      : run case CaseAsymEncryptSm2PkeDataSize470Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptSm2PkeDataSize470Multi);

/**
 * @testcase.name      : CaseAsymEncryptSm2PkeDataSize1024Once
 * @testcase.desc      : run case CaseAsymEncryptSm2PkeDataSize1024Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptSm2PkeDataSize1024Once);

/**
 * @testcase.name      : CaseAsymEncryptSm2PkeDataSize1024Multi
 * @testcase.desc      : run case CaseAsymEncryptSm2PkeDataSize1024Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymEncryptSm2PkeDataSize1024Multi);

/**
 * @testcase.name      : CaseAsymSignRsaV15Sha384KeySize2048Once
 * @testcase.desc      : run case CaseAsymSignRsaV15Sha384KeySize2048Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymSignRsaV15Sha384KeySize2048Once);

/**
 * @testcase.name      : CaseAsymSignRsaV15Sha384KeySize2048Multi
 * @testcase.desc      : run case CaseAsymSignRsaV15Sha384KeySize2048Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymSignRsaV15Sha384KeySize2048Multi);

/**
 * @testcase.name      : CaseAsymSignRsaV15Sha512KeySize4096Once
 * @testcase.desc      : run case CaseAsymSignRsaV15Sha512KeySize4096Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymSignRsaV15Sha512KeySize4096Once);

/**
 * @testcase.name      : CaseAsymSignRsaV15Sha512KeySize4096Multi
 * @testcase.desc      : run case CaseAsymSignRsaV15Sha512KeySize4096Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymSignRsaV15Sha512KeySize4096Multi);

/**
 * @testcase.name      : CaseAsymSignRsaPssSha384KeySize2048Once
 * @testcase.desc      : run case CaseAsymSignRsaPssSha384KeySize2048Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymSignRsaPssSha384KeySize2048Once);

/**
 * @testcase.name      : CaseAsymSignRsaPssSha384KeySize2048Multi
 * @testcase.desc      : run case CaseAsymSignRsaPssSha384KeySize2048Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymSignRsaPssSha384KeySize2048Multi);

/**
 * @testcase.name      : CaseAsymSignRsaPssSha512KeySize4096Once
 * @testcase.desc      : run case CaseAsymSignRsaPssSha512KeySize4096Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignRsaPssSha512KeySize4096Once);

/**
 * @testcase.name      : CaseAsymSignRsaPssSha512KeySize4096Multi
 * @testcase.desc      : run case CaseAsymSignRsaPssSha512KeySize4096Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignRsaPssSha512KeySize4096Multi);

/**
 * @testcase.name      : CaseAsymSignEcdsaSha256KeySize256Once
 * @testcase.desc      : run case CaseAsymSignEcdsaSha256KeySize256Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEcdsaSha256KeySize256Once);

/**
 * @testcase.name      : CaseAsymSignEcdsaSha256KeySize256Multi
 * @testcase.desc      : run case CaseAsymSignEcdsaSha256KeySize256Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEcdsaSha256KeySize256Multi);

/**
 * @testcase.name      : CaseAsymSignEcdsaSha384KeySize384Once
 * @testcase.desc      : run case CaseAsymSignEcdsaSha384KeySize384Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEcdsaSha384KeySize384Once);

/**
 * @testcase.name      : CaseAsymSignEcdsaSha384KeySize384Multi
 * @testcase.desc      : run case CaseAsymSignEcdsaSha384KeySize384Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEcdsaSha384KeySize384Multi);

/**
 * @testcase.name      : CaseAsymSignEcdsaSha512KeySize521Once
 * @testcase.desc      : run case CaseAsymSignEcdsaSha512KeySize521Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEcdsaSha512KeySize521Once);

/**
 * @testcase.name      : CaseAsymSignEcdsaSha512KeySize521Multi
 * @testcase.desc      : run case CaseAsymSignEcdsaSha512KeySize521Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEcdsaSha512KeySize521Multi);

/**
 * @testcase.name      : CaseAsymSignEd25519DataSize64Once
 * @testcase.desc      : run case CaseAsymSignEd25519DataSize64Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEd25519DataSize64Once);

/**
 * @testcase.name      : CaseAsymSignEd25519DataSize64Multi
 * @testcase.desc      : run case CaseAsymSignEd25519DataSize64Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEd25519DataSize64Multi);

/**
 * @testcase.name      : CaseAsymSignEd25519DataSize470Once
 * @testcase.desc      : run case CaseAsymSignEd25519DataSize470Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEd25519DataSize470Once);

/**
 * @testcase.name      : CaseAsymSignEd25519DataSize470Multi
 * @testcase.desc      : run case CaseAsymSignEd25519DataSize470Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEd25519DataSize470Multi);

/**
 * @testcase.name      : CaseAsymSignEd25519DataSize1270Once
 * @testcase.desc      : run case CaseAsymSignEd25519DataSize1270Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEd25519DataSize1270Once);

/**
 * @testcase.name      : CaseAsymSignEd25519DataSize1270Multi
 * @testcase.desc      : run case CaseAsymSignEd25519DataSize1270Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEd25519DataSize1270Multi);

/**
 * @testcase.name      : CaseAsymSignEd25519DataSize4096Once
 * @testcase.desc      : run case CaseAsymSignEd25519DataSize4096Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEd25519DataSize4096Once);

/**
 * @testcase.name      : CaseAsymSignEd25519DataSize4096Multi
 * @testcase.desc      : run case CaseAsymSignEd25519DataSize4096Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
CRYPTO_TEST_EQ(CaseAsymSignEd25519DataSize4096Multi);

/**
 * @testcase.name      : CaseAsymSignSm2DsaSm3DataSize32Once
 * @testcase.desc      : run case CaseAsymSignSm2DsaSm3DataSize32Once
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymSignSm2DsaSm3DataSize32Once);

/**
 * @testcase.name      : CaseAsymSignSm2DsaSm3DataSize32Multi
 * @testcase.desc      : run case CaseAsymSignSm2DsaSm3DataSize32Multi
 * @testcase.expect    : return TEEC_SUCCESS
 */
// CRYPTO_TEST_EQ(CaseAsymSignSm2DsaSm3DataSize32Multi);

/**
 * @testcase.name      : CaseAsymSignSm2DsaSm3DataSize128Once
 * @testcase.desc      : run case CaseAsymSignSm2DsaSm3DataSize128Once
 * @testcase.expect    : return is not TEEC_SUCCESS
 */
// CRYPTO_TEST_NE(CaseAsymSignSm2DsaSm3DataSize128Once);