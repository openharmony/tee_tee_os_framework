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

#ifndef CASE_HEADER_H_
#define CASE_HEADER_H_
#include "test_crypto_data.h"
#include "monad.h"
enum {
    CASE_PRESET_RESULT = -1,
    CASE_RAN_FLAG_SET = 1,
    CASE_RAN_FLAG_CLEAR = 0,
};

typedef struct {
    char name[MAX_STRING_NAME_LEN];
    int (*entry)(void);
    uint8_t ranFlag;
    int ret;
} CaseEntry;
// cases_sym_encrypt_basic_cases.c
int CaseSymEncryptAesEcbNopadKeySize128OnceOnce(void);
int CaseSymEncryptAesEcbNopadKeySize128OnceMulti(void);
int CaseSymEncryptAesEcbNopadKeySize128MultiOnce(void);
int CaseSymEncryptAesEcbNopadKeySize128MultiMulti(void);
int CaseSymEncryptAesCbcNopadKeySize192OnceOnce(void);
int CaseSymEncryptAesCbcNopadKeySize192OnceMulti(void);
int CaseSymEncryptAesCbcNopadKeySize192MultiOnce(void);
int CaseSymEncryptAesCbcNopadKeySize192MultiMulti(void);
int CaseSymEncryptAesCtrKeySize128OnceOnce(void);
int CaseSymEncryptAesCtrKeySize128OnceMulti(void);
int CaseSymEncryptAesCtrKeySize128MultiOnce(void);
int CaseSymEncryptAesCtrKeySize128MultiMulti(void);
int CaseSymEncryptAesXtsKeySize256OnceOnce(void);
int CaseSymEncryptAesXtsKeySize256OnceMulti(void);
int CaseSymEncryptAesXtsKeySize256MultiOnce(void);
int CaseSymEncryptAesXtsKeySize256MultiMulti(void);
int CaseSymEncryptAesCbcPkcs5KeySize256OnceOnce(void);
int CaseSymEncryptAesCbcPkcs5KeySize256OnceMulti(void);
int CaseSymEncryptAesCbcPkcs5KeySize256MultiOnce(void);
int CaseSymEncryptAesCbcPkcs5KeySize256MultiMulti(void);
int CaseSymEncryptSm4CbcNopadKeySize128OnceOnce(void);
int CaseSymEncryptSm4CbcNopadKeySize128OnceMulti(void);
int CaseSymEncryptSm4CbcNopadKeySize128MultiOnce(void);
int CaseSymEncryptSm4CbcNopadKeySize128MultiMulti(void);
int CaseSymEncryptSm4CtrKeySize128OnceOnce(void);
int CaseSymEncryptSm4CtrKeySize128OnceMulti(void);
int CaseSymEncryptSm4CtrKeySize128MultiOnce(void);
int CaseSymEncryptSm4CtrKeySize128MultiMulti(void);
int CaseSymEncryptSm4Cfb128KeySize128OnceOnce(void);
int CaseSymEncryptSm4Cfb128KeySize128OnceMulti(void);
int CaseSymEncryptSm4Cfb128KeySize128MultiOnce(void);
int CaseSymEncryptSm4Cfb128KeySize128MultiMulti(void);
int CaseSymEncryptSm4CbcPkcs7KeySize128OnceOnce(void);
int CaseSymEncryptSm4CbcPkcs7KeySize128OnceMulti(void);
int CaseSymEncryptSm4CbcPkcs7KeySize128MultiOnce(void);
int CaseSymEncryptSm4CbcPkcs7KeySize128MultiMulti(void);

// cases_ae_crypto_basic_cases.c
int CaseAEAesCcmK128N7T32Aad32MultiOnce(void);
int CaseAEAesCcmK128N7T32Aad32MultiMulti(void);
int CaseAEAesCcmK128N7T32Aad32update0Multi(void);
int CaseAEAesCcmK128N7T32Aad32OnceOnce(void);
int CaseAEAesCcmK128N7T32Aad32OnceMulti(void);
int CaseAEAesCcmK192N8T48Aad288MultiOnce(void);
int CaseAEAesCcmK192N8T48Aad288MultiMulti(void);
int CaseAEAesCcmK192N8T48Aad288OnceOnce(void);
int CaseAEAesCcmK192N8T48Aad288OnceMulti(void);
int CaseAEAesCcmK256N9T64Aad512MultiOnce(void);
int CaseAEAesCcmK256N9T64Aad512MultiMulti(void);
int CaseAEAesCcmK256N13T128Aad512OnceOnce(void);
int CaseAEAesCcmK256N13T128Aad512OnceMulti(void);
int CaseAEAesCcmK128N10T80Aad4MMultiOnce(void);
int CaseAEAesCcmK128N10T80Aad4MMultiMulti(void);
int CaseAEAesCcmK192N11T96Aad32MultiOnce(void);
int CaseAEAesCcmK192N11T96Aad32MultiMulti(void);
int CaseAEAesCcmK256N12T112Aad288MultiOnce(void);
int CaseAEAesCcmK256N12T112Aad288MultiMulti(void);
int CaseAEAesCcmK128N13T128Aad512MultiOnce(void);
int CaseAEAesCcmK128N13T128Aad512MultiMulti(void);
int CaseAEAesCcmK128N7T32Aad512EncryptOnlyTAG(void);
int CaseAEAesCcmK192N8T64NoAadOnce(void);
int CaseAEAesCcmK192N8T64NoAadMulti(void);
int CaseAEAesCcmK256N9T64Aad512DecryptOnlyTAG(void);
int CaseAEAesGcmK128N7T96Aad32MultiOnce(void);
int CaseAEAesGcmK128N7T96Aad32MultiMulti(void);
int CaseAEAesGcmK128N7T96Aad32update0Multi(void);
int CaseAEAesGcmK128N7T96Aad32OnceOnce(void);
int CaseAEAesGcmK128N7T96Aad32OnceMulti(void);
int CaseAEAesGcmK192N12T104Aad288MultiOnce(void);
int CaseAEAesGcmK192N12T104Aad288MultiMulti(void);
int CaseAEAesGcmK192N12T104Aad288OnceOnce(void);
int CaseAEAesGcmK192N12T104Aad288OnceMulti(void);
int CaseAEAesGcmK256N7T112Aad512MultiOnce(void);
int CaseAEAesGcmK256N7T112Aad512MultiMulti(void);
int CaseAEAesGcmK256N7T128Aad512OnceOnce(void);
int CaseAEAesGcmK256N7T128Aad512OnceMulti(void);
int CaseAEAesGcmK128N12T120Aad4MMultiOnce(void);
int CaseAEAesGcmK128N12T120Aad4MMultiMulti(void);
int CaseAEAesGcmK192N7T128Aad32MultiOnce(void);
int CaseAEAesGcmK192N7T128Aad32MultiMulti(void);
int CaseAEAesGcmK256N7T112Aad512DecryptOnlyTAG(void);
int CaseAEAesGcmK192N12T96NoAadOnce(void);
int CaseAEAesGcmK192N12T96NoAadMulti(void);
int CaseAEAesGcmK128N7T104Aad512EncryptOnlyTAG(void);
int CaseAESM4GcmK128N7T96Aad32MultiOnce(void);
int CaseAESM4GcmK128N7T96Aad32MultiMulti(void);
int CaseAESM4GcmK128N7T96Aad32OnceOnce(void);
int CaseAESM4GcmK128N7T96Aad32OnceMulti(void);
int CaseAESM4GcmK128N7T96Aad32update0Multi(void);
int CaseAESM4GcmK128N12T104Aad288MultiOnce(void);
int CaseAESM4GcmK128N12T104Aad288MultiMulti(void);
int CaseAESM4GcmK128N12T104Aad288OnceOnce(void);
int CaseAESM4GcmK128N12T104Aad288OnceMulti(void);
int CaseAESM4GcmK128N7T112Aad512MultiOnce(void);
int CaseAESM4GcmK128N7T112Aad512MultiMulti(void);
int CaseAESM4GcmK128N7T128Aad512OnceOnce(void);
int CaseAESM4GcmK128N7T128Aad512OnceMulti(void);
int CaseAESM4GcmK128N12T120Aad4MMultiOnce(void);
int CaseAESM4GcmK128N12T120Aad4MMultiMulti(void);
int CaseAESM4GcmK128N7T128Aad32MultiOnce(void);
int CaseAESM4GcmK128N7T128Aad32MultiMulti(void);
int CaseAESM4GcmK128N7T112Aad512DecryptOnlyTAG(void);
int CaseAESM4GcmK128N12T96NoAadOnce(void);
int CaseAESM4GcmK128N12T96NoAadMulti(void);
int CaseAESM4GcmK128N7T104Aad512EncryptOnlyTAG(void);

// cases_mac_crypto_basic_cases.c
int CaseHmacSha256KeySize64OnceOnce(void);
int CaseHmacSha256KeySize64OnceMulti(void);
int CaseHmacSha256KeySize64MultiOnce(void);
int CaseHmacSha256KeySize64MultiMulti(void);
int CaseHmacSha384KeySize1024OnceOnce(void);
int CaseHmacSha384KeySize1024OnceMulti(void);
int CaseHmacSha384KeySize1024MultiOnce(void);
int CaseHmacSha384KeySize1024MultiMulti(void);
int CaseHmacSha512KeySize256OnceOnce(void);
int CaseHmacSha512KeySize256OnceMulti(void);
int CaseHmacSha512KeySize256MultiOnce(void);
int CaseHmacSha512KeySize256MultiMulti(void);
int CaseHmacSM3KeySize512OnceOnce(void);
int CaseHmacSM3KeySize512OnceMulti(void);
int CaseHmacSM3KeySize512MultiOnce(void);
int CaseHmacSM3KeySize512MultiMulti(void);
int CaseHmacSha256KeySize8192OnceOnce(void);
int CaseHmacSha256KeySize8192OnceMulti(void);
int CaseHmacSha256KeySize8192MultiOnce(void);
int CaseHmacSha256KeySize8192MultiMulti(void);
int CaseCmacAesCbcNopadKeySize128OnceOnce(void);
int CaseCmacAesCbcNopadKeySize128OnceMulti(void);
int CaseCmacAesCbcNopadKeySize128MultiOnce(void);
int CaseCmacAesCbcNopadKeySize128MultiMulti(void);
int CaseCmacAesCbcNopadKeySize192OnceOnce(void);
int CaseCmacAesCbcNopadKeySize192OnceMulti(void);
int CaseCmacAesCbcNopadKeySize192MultiOnce(void);
int CaseCmacAesCbcNopadKeySize192MultiMulti(void);
int CaseCmacAesCbcNopadKeySize256OnceOnce(void);
int CaseCmacAesCbcNopadKeySize256OnceMulti(void);
int CaseCmacAesCbcNopadKeySize256MultiOnce(void);
int CaseCmacAesCbcNopadKeySize256MultiMulti(void);

// cases_asym_crypto_basic_cases.c
int CaseAsymEncryptRsaV15KeySize512Once(void);
int CaseAsymEncryptRsaV15KeySize2048Once(void);
int CaseAsymEncryptRsaV15KeySize2048Multi(void);
int CaseAsymEncryptRsaV15KeySize4096Once(void);
int CaseAsymEncryptRsaV15KeySize4096Multi(void);
int CaseAsymEncryptRsaOaepSha384KeySize2048Once(void);
int CaseAsymEncryptRsaOaepSha384KeySize2048Multi(void);
int CaseAsymEncryptRsaOaepSha512KeySize4096Once(void);
int CaseAsymEncryptRsaOaepSha512KeySize4096Multi(void);
int CaseAsymEncryptRsaNopadKeySize2688Once(void);
int CaseAsymEncryptRsaNopadKeySize2688Multi(void);
int CaseAsymEncryptRsaNopadKeySize4096Once(void);
int CaseAsymEncryptRsaNopadKeySize4096Multi(void);
int CaseAsymEncryptSm2PkeDataSize64Once(void);
int CaseAsymEncryptSm2PkeDataSize64Multi(void);
int CaseAsymEncryptSm2PkeDataSize470Once(void);
int CaseAsymEncryptSm2PkeDataSize470Multi(void);
int CaseAsymEncryptSm2PkeDataSize1024Once(void);
int CaseAsymEncryptSm2PkeDataSize1024Multi(void);

// cases_asym_sign_basic_cases.c
int CaseAsymSignRsaV15Sha384KeySize2048Once(void);
int CaseAsymSignRsaV15Sha384KeySize2048Multi(void);
int CaseAsymSignRsaV15Sha512KeySize4096Once(void);
int CaseAsymSignRsaV15Sha512KeySize4096Multi(void);
int CaseAsymSignRsaPssSha384KeySize2048Once(void);
int CaseAsymSignRsaPssSha384KeySize2048Multi(void);
int CaseAsymSignRsaPssSha512KeySize4096Once(void);
int CaseAsymSignRsaPssSha512KeySize4096Multi(void);
int CaseAsymSignEcdsaSha256KeySize256Once(void);
int CaseAsymSignEcdsaSha256KeySize256Multi(void);
int CaseAsymSignEcdsaSha384KeySize384Once(void);
int CaseAsymSignEcdsaSha384KeySize384Multi(void);
int CaseAsymSignEcdsaSha512KeySize521Once(void);
int CaseAsymSignEcdsaSha512KeySize521Multi(void);
int CaseAsymSignEd25519DataSize64Once(void);
int CaseAsymSignEd25519DataSize64Multi(void);
int CaseAsymSignEd25519DataSize470Once(void);
int CaseAsymSignEd25519DataSize470Multi(void);
int CaseAsymSignEd25519DataSize1270Once(void);
int CaseAsymSignEd25519DataSize1270Multi(void);
int CaseAsymSignEd25519DataSize4096Once(void);
int CaseAsymSignEd25519DataSize4096Multi(void);
int CaseAsymSignSm2DsaSm3DataSize32Once(void);
int CaseAsymSignSm2DsaSm3DataSize32Multi(void);
int CaseAsymSignSm2DsaSm3DataSize128Once(void);

// cases_digest_crypto_basic_cases.c
int CaseDigestSha256OnceOnce(void);
int CaseDigestSha256OnceMulti(void);
int CaseDigestSha256MultiOnce(void);
int CaseDigestSha256MultiMulti(void);
int CaseDigestSha384OnceOnce(void);
int CaseDigestSha384OnceMulti(void);
int CaseDigestSha384MultiOnce(void);
int CaseDigestSha384MultiMulti(void);
int CaseDigestSha512OnceOnce(void);
int CaseDigestSha512OnceMulti(void);
int CaseDigestSha512MultiOnce(void);
int CaseDigestSha512MultiMulti(void);
int CaseDigestSM3OnceOnce(void);
int CaseDigestSM3OnceMulti(void);
int CaseDigestSM3MultiOnce(void);
int CaseDigestSM3MultiMulti(void);

// cases_derive_basic_cases.c
int CaseDREcdhNistP224DataSize14(void);
int CaseDREcdhNistP256DataSize128(void);
int CaseDREcdhNistP384DataSize512(void);
int CaseDREcdhNistP521DataSize1024(void);
int CaseDREcdhNistP521DataSize4096(void);
int CaseDREcdhNistP384DataSize10000(void);
int CaseDRDHKeySize512Pram512DataSize1024(void);
int CaseDRDHKeySize1024Pram1024DataSize1024(void);
int CaseDRX25519DataSize1024(void);
int CaseDRX25519DataSize4096(void);

// cases_entry.c
int RunCaseEntryById(uint32_t startId, uint32_t runCnt, uint32_t cf);
int RunCaseEntryByName(const char *name, uint32_t runCnt, uint32_t cf);
int GetRunCaseResult(uint32_t *runCnt, uint32_t *failCnt, uint32_t *passCnt);
#endif // CASE_HEADER_H_