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

#include "securec.h"
#include "tee_crypto_api.h"
#include "tee_crypto_hal.h"
#include "test_crypto_data.h"
#include "string.h"
#include "test_crypto_api_types.h"
#include "tee_log.h"
#include "monad.h"

static int SetupProcessInOutData(ProcessInOutData *data, size_t dataSize, size_t sliceSize)
{
    data->data = malloc(dataSize + DATA_EXPAND_SIZE);
    if (data->data == NULL) {
        tloge("[%s]:malloc data failed\n", __func__);
        return -1;
    }
    data->dataMallocSize = dataSize + DATA_EXPAND_SIZE;
    data->dataSize = dataSize;
    data->dataUsed = 0;
    data->sliceSize = sliceSize;
    data->dataMode = (sliceSize == 0) ? DATA_MODE_WHOLE : DATA_MODE_SLICE;
    data->aeTagSize = 0;
    return 0;
}
static void TearDownProcessInOutData(ProcessInOutData *data)
{
    if (data->data == NULL) {
        return;
    }
    free(data->data);
    data->data = NULL;
    data->dataMallocSize = 0;
    data->dataSize = 0;
    data->dataUsed = 0;
    data->sliceSize = 0;
    data->dataMode = 0;
    data->aeTagSize = 0;
}
static int SetupPlainCipherDecryptedData(
    ProcessInOutData *plain,
    ProcessInOutData *cipher,
    ProcessInOutData *decrypted,
    size_t dataSize, size_t sliceSize)
{
    int ret1 = SetupProcessInOutData(plain, dataSize, sliceSize);
    int ret2 = SetupProcessInOutData(cipher, dataSize, sliceSize);
    int ret3 = SetupProcessInOutData(decrypted, dataSize, sliceSize);
    if (ret1 != 0 || ret2 != 0 || ret3 != 0) {
        tloge("[%s]:setup plain, chiper, decrypted failed\n", __func__);
        TearDownProcessInOutData(plain);
        TearDownProcessInOutData(cipher);
        TearDownProcessInOutData(decrypted);
        return -1;
    }
    tlogi("[%s]:setup plain, chiper, decrypted success\n", __func__);
    return 0;
}
static int TearDownPlainCipherDecryptedData(
    ProcessInOutData *plain,
    ProcessInOutData *cipher,
    ProcessInOutData *decrypted)
{
    TearDownProcessInOutData(plain);
    TearDownProcessInOutData(cipher);
    TearDownProcessInOutData(decrypted);

    tlogi("[%s]:teardown plain, chiper, decrypted success\n", __func__);
    return 0;
}
static int TestVector2IR(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;

    AlgMapInfo *algMap = FindAlgMapInfo(tv->algName);
    if (algMap == NULL) {
        tloge("[%s]:invalid algName:%s\n", __func__, tv->algName);
        return -1;
    }
    ir->algMap = algMap;

    KeyTypeMapInfo *fwdKeyMap = FindKeyTypeValue(tv->fwdKeyTypeName);
    KeyTypeMapInfo *bckKeyMap = FindKeyTypeValue(tv->bckKeyTypeName[0] == '\0' ?
        tv->fwdKeyTypeName : tv->bckKeyTypeName);
    if (fwdKeyMap == NULL || bckKeyMap == NULL) {
        tlogi("[%s]:could not fwdKeyTypeName or bckKeyTypeName, maybe this operation need no key.\n", __func__);
    } else {
        ir->fwdKeyMap = fwdKeyMap;
        ir->bckKeyMap = bckKeyMap;
        ir->fwdKeyType = fwdKeyMap->keyType;
        ir->bckKeyType = bckKeyMap->keyType;
        ir->genKeyType = fwdKeyMap->keyGenType;
    }

    ir->algValue = algMap->algValue;
    ir->algOperaClassValue = algMap->algOperaClassValue;
    ir->fwdMode = algMap->fwdMode;
    ir->bckMode = algMap->bckMode;
    ir->operaKeyCount = algMap->operaKeyCount;
    ir->needKeyCount = algMap->needKeyCount;
    ir->isSwitchFwdBckOperaKey = algMap->isSwitchFwdBckOperaKey;
    ir->operaMaxKeySize = tv->operaMaxKeySize;
    ir->keySize = tv->keySize;
    ir->dataSize = tv->dataSize;
    ir->sliceSize = tv->sliceSize;
    ir->fwdEngine = tv->fwdEngine;
    ir->bckEngine = tv->bckEngine;
    ir->ivLen = tv->ivLen;
    // ae
    ir->aeNonceLen = tv->aeNonceLen;
    ir->aeAadLenInit = tv->aeAadLenInit;
    ir->nonceByte = tv->nonceByte;
    ir->aeTagLen = tv->aeTagLen;
    ir->aeTagOSize = tv->aeTagOSize;
    ir->aeAadLen = tv->aeAadLen;
    ir->aadByte = tv->aadByte;
    // as encry and sign
    ir->rsaEnMgf1Hash = tv->rsaEnMgf1Hash;
    ir->rsaSgPssLen = tv->rsaSgPssLen;
    // gen params
    ir->ecKeyCurve = tv->ecKeyCurve;
    ir->rsaGenPubExpId = tv->rsaGenPubExpId;
    ir->dhGenKeySize = tv->dhGenKeySize;
    return 0;
}

static void IRAEDataTearDown(IntermediateReprestation *ir)
{
    if (ir->pAad == NULL) {
        tlogi("[%s]:pAad is null, just return\n", __func__);
        return;
    }
    TEE_Free(ir->pAad);
    ir->pAad = NULL;

    tlogi("[%s]:IRAEDataTearDown down\n", __func__);
    return;
}
static int IRAEDataSetUp(IntermediateReprestation *ir)
{
    // aad data setup
    if (ir->aeAadLen == 0) {
        tlogi("[%s]:ir->aeAadLen is zero, just return\n", __func__);
        return 0;
    }
    ir->pAad = TEE_Malloc(ir->aeAadLen, 0);
    if (ir->pAad == NULL) {
        tlogi("[%s]:TEE_Malloc ir->aeAadLen %u failed\n", __func__);
        return -1;
    }
    size_t i;
    for (i = 0; i < ir->aeAadLen; i++) {
        ir->pAad[i] = ir->aadByte;
    }

    // nonce data setup
    for (i = 0; i < ir->aeNonceLen; i++) {
        ir->nonce[i] = ir->nonceByte;
    }

    tlogi("[%s]:IRAEDataSetUp success\n", __func__);
    return 0;
}

static int IRDataTearDown(IntermediateReprestation *ir)
{
    // teardown plain cipher decrypted data
    int ret = TearDownPlainCipherDecryptedData(&(ir->plainData),
        &(ir->cipherData), &(ir->decryptedData));
    if (ret != 0) {
        tloge("[%s]:TearDownPlainCipherDecryptedData failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:TearDownPlainCipherDecryptedData success\n", __func__);

    // teardown ae data
    IRAEDataTearDown(ir);
    tlogi("[%s]:IRAEDataTearDown done\n", __func__);
    return 0;
}
static int IRDataSetup(IntermediateReprestation *ir)
{
    // setup plain cipher decrypted data
    int ret = SetupPlainCipherDecryptedData(&(ir->plainData),
        &(ir->cipherData), &(ir->decryptedData),
        ir->dataSize, ir->sliceSize);
    if (ret != 0) {
        tloge("[%s]:SetupPlainCipherDecryptedData failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:SetupPlainCipherDecryptedData success\n", __func__);

    // setup AE data
    ret = IRAEDataSetUp(ir);
    if (ret != 0) {
        tloge("[%s]:IRAEDataSetUp failed\n", __func__);
        IRDataTearDown(ir);
        return -1;
    }

    tlogi("[%s]:IRDataSetup success\n", __func__);
    return 0;
}

int IRSetUp(IntermediateReprestation *ir)
{
    int ret = TestVector2IR(ir);
    if (ret != 0) {
        tloge("[%s]:TestVector2IR failed\n", __func__);
        return -1;
    }

    ret = IRDataSetup(ir);
    if (ret != 0) {
        tloge("[%s]:IRDataSetup failed\n", __func__);
        return -1;
    }

    ret = DisbalanceGroupElement(ir->mrpl, ir->mrplSize, IRSetUp);
    if (ret != 0) {
        tloge("[%s]:DisbalanceGroupElement failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:IRSetUp success\n", __func__);
    return 0;
}
int IRTearDown(IntermediateReprestation *ir)
{
    int ret = IRDataTearDown(ir);
    if (ret != 0) {
        tloge("[%s]:IRDataTearDown failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:IRDataTearDown success\n", __func__);
    ret = BalanceGroupElement(ir->mrpl, ir->mrplSize, IRTearDown);
    if (ret != 0) {
        tloge("[%s]:BalanceGroupElement failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:IRTearDown success\n", __func__);
    return 0;
}
int GlbFree(IntermediateReprestation *ir)
{
    if (ir->fwdOperaHandle != NULL) {
        TEE_FreeOperation(ir->fwdOperaHandle);
    }

    if (ir->bckOperaHandle != NULL) {
        TEE_FreeOperation(ir->bckOperaHandle);
    }

    int ret = BalanceGroupElement(ir->mrpl, ir->mrplSize, GlbFree);
    if (ret != 0) {
        tloge("[%s]:BalanceGroupElement failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:GlbFree success\n", __func__);
    return 0;
}
int GlbAlloc(IntermediateReprestation *ir)
{
    (void)ir;
    ir->fwdOperaHandle = NULL;
    ir->bckOperaHandle = NULL;
    TEE_Result ret1 = TEE_AllocateOperation(&(ir->fwdOperaHandle), ir->algValue,
        ir->fwdMode, ir->operaMaxKeySize);
    TEE_Result ret2 = TEE_AllocateOperation(&(ir->bckOperaHandle), ir->algValue,
        ir->bckMode, ir->operaMaxKeySize);
    if (ret1 != TEE_SUCCESS || ret2 != TEE_SUCCESS) {
        tloge("[%s]:allocate fwdOperaHandle or bckOperaHandle\n", __func__);
        goto error;
    }

    ret1 = TEE_SetCryptoFlag(ir->fwdOperaHandle, SOFT_CRYPTO);
    ret2 = TEE_SetCryptoFlag(ir->bckOperaHandle, SOFT_CRYPTO);
    if (ret1 != TEE_SUCCESS || ret2 != TEE_SUCCESS) {
        tloge("[%s]:allocate fwdOperaHandle or bckOperaHandle\n", __func__);
        goto error;
    }
    tlogi("[%s]:TEE_AllocateOperation fwd and bck operation handle success.\n", __func__);

    int ret = DisbalanceGroupElement(ir->mrpl, ir->mrplSize, GlbAlloc);
    if (ret != 0) {
        tloge("[%s]:DisbalanceGroupElement failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:GlbAlloc success\n", __func__);
    return 0;
error:
    GlbFree(ir);
    return -1;
}

int GlbGetInfo(IntermediateReprestation *ir)
{
    TEE_OperationInfo operationInfo = {0};
    TEE_GetOperationInfo(ir->fwdOperaHandle, &operationInfo);
    tlogi("[%s]:GlbGetInfo success\n", __func__);
    return 0;
}

int GlbGetInfoMulti(IntermediateReprestation *ir)
{
    TEE_Result ret = TEE_SUCCESS;
    int test_ret = -1;
    size_t operationSize = sizeof(TEE_OperationInfoMultiple) + 2 * sizeof(TEE_OperationInfoKey);
    TEE_OperationInfoMultiple *operationInfoMultiple = (TEE_OperationInfoMultiple *)TEE_Malloc(operationSize, 0);
    if (operationInfoMultiple == NULL)
    {
        tloge("operation info multiple malloc failed\n");
        return test_ret;
    }

    ret = TEE_GetOperationInfoMultiple(ir->fwdOperaHandle, operationInfoMultiple, &operationSize);
    if (ret != TEE_SUCCESS)
    {
        tloge("TEE_GetOperationInfoMultipe failed(%x).\n", ret);
        return test_ret;
    }
    
    tlogi("[%s]:GlbGetInfoMulti success\n", __func__);
    return 0;
}

int GlbReset(IntermediateReprestation *ir)
{
    TEE_ResetOperation(ir->fwdOperaHandle);
    tlogi("[%s]:GlbReset success\n", __func__);
    return 0;
}

static void FreeFourKeyObj(TEE_ObjectHandle fwdKey0, TEE_ObjectHandle fwdKey1,
    TEE_ObjectHandle bckKey0, TEE_ObjectHandle bckKey1)
{
    if (fwdKey0 != NULL) {
        TEE_FreeTransientObject(fwdKey0);
    }
    if (fwdKey1 != NULL) {
        TEE_FreeTransientObject(fwdKey1);
    }
    if (bckKey0 != NULL) {
        TEE_FreeTransientObject(bckKey0);
    }
    if (bckKey1 != NULL) {
        TEE_FreeTransientObject(bckKey1);
    }
}
int AllocateFourKeyObj(TEE_ObjectHandle *fwdKey0, TEE_ObjectHandle *fwdKey1,
    TEE_ObjectHandle *bckKey0, TEE_ObjectHandle *bckKey1, IntermediateReprestation *ir)
{
    TEE_Result ret1 = TEE_AllocateTransientObject(ir->fwdKeyType, ir->keySize, fwdKey0);
    TEE_Result ret2 = TEE_AllocateTransientObject(ir->fwdKeyType, ir->keySize, fwdKey1);
    TEE_Result ret3 = TEE_AllocateTransientObject(ir->bckKeyType, ir->keySize, bckKey0);
    TEE_Result ret4 = TEE_AllocateTransientObject(ir->bckKeyType, ir->keySize, bckKey1);
    if (ret1 != TEE_SUCCESS || ret2 != TEE_SUCCESS ||
        ret3 != TEE_SUCCESS || ret4 != TEE_SUCCESS) {
        tloge("[%s]:TEE_AllocateTransientObject fwdKey0, fwdKey1, bckKey0, bckKey1 failed\n",
            __func__);
        goto error1;
    }
    tlogi("[%s]:AllocateFourKeyObj success\n", __func__);
    return 0;
error1:
    FreeFourKeyObj(*fwdKey0, *fwdKey1, *bckKey0, *bckKey1);
    return -1;
}
int CopyKeyAndSetOperationKey(TEE_ObjectHandle *fwdKey0, TEE_ObjectHandle *fwdKey1,
    TEE_ObjectHandle *bckKey0, TEE_ObjectHandle *bckKey1, IntermediateReprestation *ir)
{
    int ret = GetOrGenIRTestKeys(ir);
    if (ret != 0) {
        tloge("[%s]:GetOrGenIRTestKeys failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:GetOrGenIRTestKeys success\n", __func__);

    TestKeyItem *keyItem = ir->tki;

    TEE_CopyObjectAttributes1(*fwdKey0, keyItem->keyObjList[0]);
    TEE_CopyObjectAttributes1(*fwdKey1, keyItem->keyObjList[1]);
    if (ir->isSwitchFwdBckOperaKey) {
        TEE_CopyObjectAttributes1(*bckKey0, keyItem->keyObjList[1]);
        TEE_CopyObjectAttributes1(*bckKey1, keyItem->keyObjList[0]);
    } else {
        TEE_CopyObjectAttributes1(*bckKey0, keyItem->keyObjList[0]);
        TEE_CopyObjectAttributes1(*bckKey1, keyItem->keyObjList[1]);
    }
    int ret1 = 0;
    int ret2 = 0;
    if (ir->operaKeyCount == XTS_KEY_COUNT_TWO) {
        ret1 = TEE_SetOperationKey2(ir->fwdOperaHandle, *fwdKey0, *fwdKey1);
        ret2 = TEE_SetOperationKey2(ir->bckOperaHandle, *bckKey0, *bckKey1);
    } else {
        ret1 = TEE_SetOperationKey(ir->fwdOperaHandle, *fwdKey0);
        ret2 = TEE_SetOperationKey(ir->bckOperaHandle, *bckKey0);
    }
    if (ret1 != TEE_SUCCESS || ret2 != TEE_SUCCESS) {
        tloge("[%s]:TEE_CopyObjectAttributes1 fwdKey0, fwdKey1, bckKey0, bckKey1 failed\n", __func__);
        return -1;
    }
    return 0;
}
int GlbS1S2(IntermediateReprestation *ir)
{
    TEE_ObjectHandle fwdKey0 = NULL;
    TEE_ObjectHandle fwdKey1 = NULL;
    TEE_ObjectHandle bckKey0 = NULL;
    TEE_ObjectHandle bckKey1 = NULL;
    int ret = AllocateFourKeyObj(&fwdKey0, &fwdKey1, &bckKey0, &bckKey1, ir);
    if (ret != 0) {
        tloge("[%s]:AllocateFourKeyObj falied\n", __func__);
        return -1;
    }
    ret = CopyKeyAndSetOperationKey(&fwdKey0, &fwdKey1, &bckKey0, &bckKey1, ir);
    if (ret != 0) {
        tloge("[%s]:CopyKeyAndSetOperationKey falied\n", __func__);
        goto error;
    }
    tlogi("[%s]GlbS1S2 success\n", __func__);
error:
    FreeFourKeyObj(fwdKey0, fwdKey1, bckKey0, bckKey1);
    return ret;
}

int GlbS1S2Null(IntermediateReprestation *ir)
{
    (void)ir;
    tlogi("in function [%s]\n", __func__);
    return 0;
}

#define AES_KEY_SIZE_MAX 128
int GlbCopy(IntermediateReprestation *ir)
{
    TEE_OperationHandle tmp = NULL;
    TEE_Result ret = TEE_AllocateOperation(&tmp, TEE_ALG_AES_CBC_PKCS5, TEE_MODE_ENCRYPT, AES_KEY_SIZE_MAX);
    if (ret != TEE_SUCCESS) {
        tloge("[%s] TEE_AllocateOperation aes cbc encrypted operation fail, ret 0x%x\n", __func__, ret);
        return ret;
    }
    TEE_CopyOperation(tmp, ir->fwdOperaHandle);
    TEE_FreeOperation(tmp);
    tlogi("[%s]GlbCopy success\n", __func__);
    return 0;
}

int GlbCopyRpl(IntermediateReprestation *ir)
{
    (void)ir;
    tlogi("in function [%s]\n", __func__);
    return 0;
}

int GlbIsAlgSprt(IntermediateReprestation *ir)
{
    (void)ir;
    TEE_Result ret = TEE_IsAlgorithmSupported(TEE_ALG_AES_ECB_NOPAD, TEE_OPTIONAL_ELEMENT_NONE);
    if (ret != TEE_SUCCESS) {
        tloge("[%s] TEE_IsAlogrithmSupported test failed. ret = 0x%x\n", __func__, ret);
        return TEE_ERROR_GENERIC;
    }
    
    tlogi("[%s]: test TEE_IsAlogrithmSupported success\n", __func__);
    return 0;
}

int DIUpdateFwd(IntermediateReprestation *ir)
{
    if (ir->plainData.dataMode == DATA_MODE_WHOLE) {
        tlogi("[%s]:dataMode is whole, not slice, just return.\n", __func__);
        return 0;
    }
    void *chunk = ir->plainData.data + ir->plainData.dataUsed;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    size_t chunkSize = (dataLeft >= ir->plainData.sliceSize) ? ir->plainData.sliceSize :  0;
    TEE_DigestUpdate(ir->fwdOperaHandle, (const void *)chunk, chunkSize);
    ir->plainData.dataUsed += chunkSize;

    tlogi("[%s]:DIUpdateFwd success.\n", __func__);
    return 0;
}

typedef struct {
    uint32_t alg;
    uint32_t len;
} DigestMacLenMap;
enum {
    LEN_8 = 8,
    LEN_16 = 16,
    LEN_20 = 20,
    LEN_28 = 28,
    LEN_32 = 32,
    LEN_48 = 48,
    LEN_64 = 64,
};
static DigestMacLenMap g_digestMacLenMapList[] = {
    // digest
    { .alg = TEE_ALG_MD5, .len = LEN_16, },
    { .alg = TEE_ALG_SHA1, .len = LEN_20, },
    { .alg = TEE_ALG_SHA224, .len = LEN_28, },
    { .alg = TEE_ALG_SHA256, .len = LEN_32, },
    { .alg = TEE_ALG_SHA384, .len = LEN_48, },
    { .alg = TEE_ALG_SHA512, .len = LEN_64, },
    { .alg = TEE_ALG_SM3, .len = LEN_32, },
    // hmac
    { .alg = TEE_ALG_HMAC_MD5, .len = LEN_16, },
    { .alg = TEE_ALG_HMAC_SHA1, .len = LEN_20, },
    { .alg = TEE_ALG_HMAC_SHA224, .len = LEN_28, },
    { .alg = TEE_ALG_HMAC_SHA256, .len = LEN_32, },
    { .alg = TEE_ALG_HMAC_SHA384, .len = LEN_48, },
    { .alg = TEE_ALG_HMAC_SHA512, .len = LEN_64, },
    { .alg = TEE_ALG_HMAC_SM3, .len = LEN_32, },
    { .alg = TEE_ALG_AES_CMAC, .len = LEN_16, },
    { .alg = TEE_ALG_AES_CBC_MAC_NOPAD, .len = LEN_16, },
    { .alg = TEE_ALG_DES3_CBC_MAC_NOPAD, .len = LEN_8, },
    { .alg = TEE_ALG_DES_CBC_MAC_NOPAD, .len = LEN_8, },
};
static size_t g_digestMacLenMapListSize = sizeof(g_digestMacLenMapList) / sizeof(g_digestMacLenMapList[0]);
static int CheckDigestMacLen(uint32_t alg, size_t len)
{
    size_t i;
    for (i = 0; i < g_digestMacLenMapListSize; i++) {
        if (g_digestMacLenMapList[i].alg == alg && g_digestMacLenMapList[i].len == len) {
            tlogi("[%s]:find expect alg 0x%x and len %lu\n", __func__, alg, len);
            return 0;
        }
    }
    tloge("[%s]:could not find alg 0x%x len map\n", __func__, alg);
    return 0;
}

int DIDofinalFwd(IntermediateReprestation *ir)
{
    int ret;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    while (ir->plainData.dataMode != DATA_MODE_WHOLE &&
        dataLeft > ir->plainData.sliceSize) {
            ret = DIUpdateFwd(ir);
            if (ret != 0) {
                tloge("[%s]:DIUpdateFwd failed\n", __func__);
                return -1;
            }
            dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    }
    void *chunk = ir->plainData.data + ir->plainData.dataUsed;
    size_t chunkLen = dataLeft;
    void *hash = ir->cipherData.data;
    size_t hashLen = ir->cipherData.dataSize;
    ret = TEE_DigestDoFinal(ir->fwdOperaHandle, (const void *)chunk, chunkLen, hash, &(hashLen));
    if (ret != 0) {
        tloge("[%s]:TEE_DigestDoFinal failed, ret = 0x%x\n", __func__, ret);
        return -1;
    }
    tlogi("[%s]:TEE_DigestDoFinal success\n", __func__);

    ret = CheckDigestMacLen(ir->algMap->algValue, hashLen);
    if (ret != 0) {
        tloge("[%s]:CheckDigestMacLen failed\n", __func__);
        return -1;
    }
    ir->cipherData.dataSize = hashLen;
    ir->plainData.dataUsed = 0;
    tlogi("[%s]:DIDofinalFwd success\n", __func__);
    return 0;
}

int DIUpdateBck(IntermediateReprestation *ir)
{
    if (ir->plainData.dataMode == DATA_MODE_WHOLE) {
        tlogi("[%s]:dataMode is whole, not slice, just return.\n", __func__);
        return 0;
    }
    void *chunk = ir->plainData.data + ir->plainData.dataUsed;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    size_t chunkSize = (dataLeft >= ir->plainData.sliceSize) ? ir->plainData.sliceSize :  0;
    TEE_DigestUpdate(ir->bckOperaHandle, (const void *)chunk, chunkSize);
    ir->plainData.dataUsed += chunkSize;

    tlogi("[%s]:DIUpdateBck success.\n", __func__);
    return 0;
}

int DIDofinalBck(IntermediateReprestation *ir)
{
    int ret;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    while (ir->plainData.dataMode != DATA_MODE_WHOLE &&
        dataLeft > ir->plainData.sliceSize) {
            ret = DIUpdateBck(ir);
            if (ret != 0) {
                tloge("[%s]:DIUpdateBck failed\n", __func__);
                return -1;
            }
            dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    }
    void *chunk = ir->plainData.data + ir->plainData.dataUsed;
    size_t chunkLen = dataLeft;
    void *hash = ir->decryptedData.data;
    size_t hashLen = ir->decryptedData.dataSize;
    ret = TEE_DigestDoFinal(ir->bckOperaHandle, (const void *)chunk, chunkLen, hash, &(hashLen));
    if (ret != 0) {
        tloge("[%s]:TEE_DigestDoFinal failed, ret = 0x%x\n", __func__, ret);
        return -1;
    }
    tlogi("[%s]:TEE_DigestDoFinal success\n", __func__);

    ret = CheckDigestMacLen(ir->algMap->algValue, hashLen);
    if (ret != 0) {
        tloge("[%s]:CheckDigestMacLen failed\n", __func__);
        return -1;
    }
    ir->decryptedData.dataSize = hashLen;
    ir->plainData.dataUsed = 0;

    if (TEE_MemCompare((void *)ir->cipherData.data,
        (void *)ir->decryptedData.data,
        (size_t)ir->cipherData.dataSize)) {
        tloge("[%s]:TEE_MemCompare failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:DIDofinalBck success\n", __func__);
    return 0;
}

#define MAX_IV_BUFFER_SIZE 64
#define IV_VALUE 0x7F
static void *GetIvAddr(void)
{
    static int initFlag = 0;
    static uint8_t iv[MAX_IV_BUFFER_SIZE];
    if (initFlag != 0) {
        goto ret;
    }
    int i;
    for (i = 0; i < MAX_IV_BUFFER_SIZE; i++) {
        iv[i] = IV_VALUE;
    }
    initFlag = 1;
ret:
    return iv;
}
int SCInitFwd(IntermediateReprestation *ir)
{
    ir->plainData.dataUsed = 0;
    ir->cipherData.dataSize = ir->cipherData.dataMallocSize;
    ir->cipherData.dataUsed = 0;
    TEE_CipherInit(ir->fwdOperaHandle, (void *)GetIvAddr(), ir->ivLen);
    tlogi("[%s]SCInitFwd success\n", __func__);
    return 0;
}

int SCUpdateFwd(IntermediateReprestation *ir)
{
    if (ir->plainData.dataMode == DATA_MODE_WHOLE) {
        tlogi("[%s]:dataMode is whole, not slice, just return.\n", __func__);
        return 0;
    }
    void *pSrcData = ir->plainData.data + ir->plainData.dataUsed;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    size_t srcLen = (dataLeft >= ir->plainData.sliceSize) ? ir->plainData.sliceSize :  0;
    void *pDestData = ir->cipherData.data + ir->cipherData.dataUsed;
    size_t destLen = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    int ret = TEE_CipherUpdate(ir->fwdOperaHandle, pSrcData, srcLen, pDestData, &destLen);
    if (ret != 0) {
        tloge("[%s]:TEE_CipherUpdate failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }
    ir->plainData.dataUsed += srcLen;
    ir->cipherData.dataUsed += destLen;
    tlogi("[%s]:SCUpdateFwd success.\n", __func__);
    return 0;
}

int SCDofinalFwd(IntermediateReprestation *ir)
{
    int ret;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    while (ir->plainData.dataMode != DATA_MODE_WHOLE &&
        dataLeft > ir->plainData.sliceSize) {
            ret = SCUpdateFwd(ir);
            if (ret != 0) {
                tloge("[%s]:SCUpdateFwd failed\n", __func__);
                return -1;
            }
            dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    }
    void *pSrcData = ir->plainData.data + ir->plainData.dataUsed;
    size_t srcLen = dataLeft;
    void *pDestData = ir->cipherData.data + ir->cipherData.dataUsed;
    size_t destLen = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    ret = TEE_CipherDoFinal(ir->fwdOperaHandle, pSrcData, srcLen, pDestData, &destLen);
    if (ret != 0) {
        tloge("[%s]:TEE_CipherDoFinal failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }
    ir->cipherData.dataSize = ir->cipherData.dataUsed + destLen;
    tlogi("[%s]:SCDofinalFwd success\n", __func__);
    return 0;
}

int SCInitBck(IntermediateReprestation *ir)
{
    ir->cipherData.dataUsed = 0;
    ir->decryptedData.dataSize = ir->decryptedData.dataMallocSize;
    ir->decryptedData.dataUsed = 0;
    TEE_CipherInit(ir->bckOperaHandle, (void *)GetIvAddr(), ir->ivLen);
    tlogi("[%s]SCInitBck success\n", __func__);
    return 0;
}

int SCUpdateBck(IntermediateReprestation *ir)
{
    if (ir->plainData.dataMode == DATA_MODE_WHOLE) {
        tlogi("[%s]:dataMode is whole, not slice, just return.\n", __func__);
        return 0;
    }
    void *pSrcData = ir->cipherData.data + ir->cipherData.dataUsed;
    size_t dataLeft = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    size_t srcLen = (dataLeft >= ir->cipherData.sliceSize) ? ir->cipherData.sliceSize :  0;
    void *pDestData = ir->decryptedData.data + ir->decryptedData.dataUsed;
    size_t destLen = ir->decryptedData.dataSize - ir->decryptedData.dataUsed;
    int ret = TEE_CipherUpdate(ir->bckOperaHandle, pSrcData, srcLen, pDestData, &destLen);
    if (ret != 0) {
        tloge("[%s]:TEE_CipherUpdate failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }
    ir->cipherData.dataUsed += srcLen;
    ir->decryptedData.dataUsed += destLen;
    tlogi("[%s]:SCUpdateBck success.\n", __func__);
    return 0;
}

int SCDofinalBck(IntermediateReprestation *ir)
{
    int ret;
    size_t dataLeft = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    while (ir->cipherData.dataMode != DATA_MODE_WHOLE &&
        dataLeft > ir->cipherData.sliceSize) {
            ret = SCUpdateBck(ir);
            if (ret != 0) {
                tloge("[%s]:SCUpdateBck failed\n", __func__);
                return -1;
            }
            dataLeft = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    }
    void *pSrcData = ir->cipherData.data + ir->cipherData.dataUsed;
    size_t srcLen = dataLeft;
    void *pDestData = ir->decryptedData.data + ir->decryptedData.dataUsed;
    size_t destLen = ir->decryptedData.dataSize - ir->decryptedData.dataUsed;
    ret = TEE_CipherDoFinal(ir->bckOperaHandle, pSrcData, srcLen, pDestData, &destLen);
    if (ret != 0) {
        tloge("[%s]:TEE_CipherDoFinal failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }
    ir->decryptedData.dataSize = ir->decryptedData.dataUsed + destLen;
    tlogi("[%s]:TEE_CipherDoFinal success\n", __func__);
    
    if (TEE_MemCompare((void *)ir->plainData.data,
        (void *)ir->decryptedData.data,
        (size_t)ir->plainData.dataSize)) {
        tloge("[%s]:TEE_MemCompare failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:SCDofinalFwd success\n", __func__);
    return 0;
}

int MInitFwd(IntermediateReprestation *ir)
{
    ir->plainData.dataUsed = 0;
    ir->cipherData.dataSize = ir->cipherData.dataMallocSize;
    ir->cipherData.dataUsed = 0;
    TEE_MACInit(ir->fwdOperaHandle, (void *)GetIvAddr(), ir->ivLen);
    tlogi("[%s]:MInitFwd success\n", __func__);
    return 0;
}

int MUpdateFwd(IntermediateReprestation *ir)
{
    if (ir->plainData.dataMode == DATA_MODE_WHOLE) {
        tlogi("[%s]:dataMode is whole, not slice, just return.\n", __func__);
        return 0;
    }
    void *chunk = ir->plainData.data + ir->plainData.dataUsed;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    size_t chunkSize = (dataLeft >= ir->plainData.sliceSize) ? ir->plainData.sliceSize :  0;
    TEE_MACUpdate(ir->fwdOperaHandle, (const void *)chunk, chunkSize);
    ir->plainData.dataUsed += chunkSize;
    tlogi("[%s]:MUpdateFwd success.\n", __func__);
    return 0;
}

int MComputeFwd(IntermediateReprestation *ir)
{
    int ret;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    while (ir->plainData.dataMode != DATA_MODE_WHOLE &&
        dataLeft > ir->plainData.sliceSize) {
            ret = MUpdateFwd(ir);
            if (ret != 0) {
                tloge("[%s]:MUpdateFwd failed\n", __func__);
                return -1;
            }
            dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    }
    void *message = ir->plainData.data + ir->plainData.dataUsed;
    size_t messageLen = dataLeft;
    void *mac = ir->cipherData.data;
    size_t macLen = ir->cipherData.dataSize;
    ret = TEE_MACComputeFinal(ir->fwdOperaHandle, (const void *)message, messageLen,
        mac, &macLen);
    if (ret != 0) {
        tloge("[%s]:TEE_MACComputeFinal failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }
    ir->cipherData.dataSize = macLen;
    tlogi("[%s]:TEE_MACComputeFinal success \n", __func__);

    ret = CheckDigestMacLen(ir->algMap->algValue, macLen);
    if (ret != 0) {
        tloge("[%s]:CheckDigestMacLen failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:MComputeFwd success\n", __func__);
    return 0;
}

int MInitBck(IntermediateReprestation *ir)
{
    ir->plainData.dataUsed = 0;
    TEE_MACInit(ir->bckOperaHandle, (void *)GetIvAddr(), ir->ivLen);
    tlogi("[%s]:MInitBck success\n", __func__);
    return 0;
}

int MUpdateBck(IntermediateReprestation *ir)
{
    if (ir->plainData.dataMode == DATA_MODE_WHOLE) {
        tlogi("[%s]:dataMode is whole, not slice, just return.\n", __func__);
        return 0;
    }
    void *chunk = ir->plainData.data + ir->plainData.dataUsed;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    size_t chunkSize = (dataLeft >= ir->plainData.sliceSize) ? ir->plainData.sliceSize :  0;
    TEE_MACUpdate(ir->bckOperaHandle, (const void *)chunk, chunkSize);
    ir->plainData.dataUsed += chunkSize;
    tlogi("[%s]:MUpdateBck success.\n", __func__);
    return 0;
}

int MCapareBck(IntermediateReprestation *ir)
{
    int ret;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    while (ir->plainData.dataMode != DATA_MODE_WHOLE &&
        dataLeft > ir->plainData.sliceSize) {
            ret = MUpdateBck(ir);
            if (ret != 0) {
                tloge("[%s]:MUpdateBck failed\n", __func__);
                return -1;
            }
            dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    }
    void *message = ir->plainData.data + ir->plainData.dataUsed;
    size_t messageLen = dataLeft;
    void *mac = ir->cipherData.data;
    size_t macLen = ir->cipherData.dataSize;
    ret = TEE_MACCompareFinal(ir->bckOperaHandle, (const void *)message, messageLen, (const void *)mac,
        (const size_t)macLen);
    if (ret != 0) {
        tloge("[%s]:TEE_MACCompareFinal failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }
    tlogi("[%s]:MCapareBck success\n", __func__);
    return 0;
}

int AEInitFwd(IntermediateReprestation *ir)
{
    ir->plainData.dataUsed = 0;
    ir->cipherData.dataSize = ir->cipherData.dataMallocSize;
    ir->cipherData.dataUsed = 0;
    int ret = TEE_AEInit(ir->fwdOperaHandle, ir->nonce, ir->aeNonceLen, ir->aeTagLen, ir->aeAadLenInit, ir->dataSize);
    if (ret != 0) {
        tloge("[%s]:TEE_AEInit failed, ret = 0x%x\n", __func__, ret);
    }
    tlogi("[%s]:TEE_AEInit success\n", __func__);
    return 0;
}

int AEUpdateAadFwd(IntermediateReprestation *ir)
{
    TEE_AEUpdateAAD(ir->fwdOperaHandle, ir->pAad, ir->aeAadLen);
    tlogi("[%s]:AEUpdateAadFwd success\n", __func__);
    return 0;
}
enum {
    MLT_UPDATE_COUNT = 3,
};
int AEUpdateAadMtlFwd(IntermediateReprestation *ir)
{
    size_t slice = ir->aeAadLen / MLT_UPDATE_COUNT;
    size_t used = 0;
    size_t left = ir->aeAadLen;
    size_t curAadLen = slice;
    size_t i;
    for (i = 0; i < MLT_UPDATE_COUNT; i++) {
        curAadLen = (i == (MLT_UPDATE_COUNT - 1) ? left : slice);
        TEE_AEUpdateAAD(ir->fwdOperaHandle, ir->pAad + used, curAadLen);
        used += curAadLen;
        left = ir->aeAadLen - used;
    }
    tlogi("[%s]:AEUpdateAadMtlFwd success\n", __func__);
    return 0;
}

int AEUpdateFwd(IntermediateReprestation *ir)
{
    if (ir->plainData.dataMode == DATA_MODE_WHOLE) {
        tlogi("[%s]:dataMode is whole, not slice, just return.\n", __func__);
        return 0;
    }

    void *pSrcData = ir->plainData.data + ir->plainData.dataUsed;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    size_t srcLen = (dataLeft >= ir->plainData.sliceSize) ? ir->plainData.sliceSize :  0;
    void *pDestData = ir->cipherData.data + ir->cipherData.dataUsed;
    size_t destLen = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    int ret = TEE_AEUpdate(ir->fwdOperaHandle, pSrcData, srcLen, pDestData, &destLen);
    if (ret != 0) {
        tloge("[%s]:TEE_AEUpdate failed\n", __func__);
        return -1;
    }

    ir->plainData.dataUsed += srcLen;
    ir->cipherData.dataUsed += destLen;

    tlogi("[%s]:AEUpdateFwd success\n", __func__);
    return 0;
}

int AEUpdate0Fwd(IntermediateReprestation *ir)
{
    void *pSrcData = ir->plainData.data + ir->plainData.dataUsed;
    size_t srcLen = 0;
    void *pDestData = ir->cipherData.data + ir->cipherData.dataUsed;
    size_t destLen = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    int ret = TEE_AEUpdate(ir->fwdOperaHandle, pSrcData, srcLen, pDestData, &destLen);
    if (ret != 0) {
        tloge("[%s]:TEE_AEUpdate failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:AEUpdate0Fwd success\n", __func__);
    return 0;
}

int AEEncFinalFwd(IntermediateReprestation *ir)
{
    int ret;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    while (ir->plainData.dataMode != DATA_MODE_WHOLE &&
        dataLeft > ir->plainData.sliceSize) {
            ret = AEUpdateFwd(ir);
            if (ret != 0) {
                tloge("[%s]:AEUpdateFwd failed\n", __func__);
                return -1;
            }
            dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    }
    void *srcData = ir->plainData.data + ir->plainData.dataUsed;
    size_t srcLen = dataLeft;
    void *destData = ir->cipherData.data + ir->cipherData.dataUsed;
    size_t destLen = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    void *tag = ir->aeTag;
    size_t tagLen = ir->aeTagOSize;
    ret = TEE_AEEncryptFinal(ir->fwdOperaHandle, srcData, srcLen, destData,
        &destLen, tag, &tagLen);
    if (ret != 0) {
        tloge("[%s]:TEE_AEEncryptFinal failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }
    ir->cipherData.dataSize = ir->cipherData.dataUsed + destLen;
    ir->aeTagOSize = tagLen;
    tlogi("[%s]:AEEncFinalFwd success\n", __func__);
    return 0;
}
int AEEncFinalOmtFwd(IntermediateReprestation *ir)
{
    int ret;
    size_t dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    while (ir->plainData.dataMode != DATA_MODE_WHOLE &&
        dataLeft > ir->plainData.sliceSize) {
            ret = AEUpdateFwd(ir);
            if (ret != 0) {
                tloge("[%s]:AEUpdateFwd failed\n", __func__);
                return -1;
            }
            dataLeft = ir->plainData.dataSize - ir->plainData.dataUsed;
    }
    void *srcData = ir->plainData.data + ir->plainData.dataUsed;
    size_t srcLen = dataLeft;
    void *tag = ir->aeTag;
    size_t tagLen = ir->aeTagOSize;
    ret = TEE_AEEncryptFinal(ir->fwdOperaHandle, srcData, srcLen, NULL,
        NULL, tag, &tagLen);
    if (ret != 0) {
        tloge("[%s]:TEE_AEEncryptFinal failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }
    ir->aeTagOSize = tagLen;
    tlogi("[%s]:AEEncFinalOmtFwd success\n", __func__);
    return 0;
}
int AEInitBck(IntermediateReprestation *ir)
{
    ir->cipherData.dataUsed = 0;
    ir->decryptedData.dataSize = ir->decryptedData.dataMallocSize;
    ir->decryptedData.dataUsed = 0;
    int ret = TEE_AEInit(ir->bckOperaHandle, ir->nonce, ir->aeNonceLen, ir->aeTagLen, ir->aeAadLenInit, ir->dataSize);
    if (ret != 0) {
        tloge("[%s]:TEE_AEInit failed, ret = 0x%x\n", __func__, ret);
    }
    tlogi("[%s]:TEE_AEInit success\n", __func__);
    return 0;
}

int AEUpdateAadBck(IntermediateReprestation *ir)
{
    TEE_AEUpdateAAD(ir->bckOperaHandle, ir->pAad, ir->aeAadLen);
    tlogi("[%s]:AEUpdateAadBck success\n", __func__);
    return 0;
}

int AEUpdateAadMtlBck(IntermediateReprestation *ir)
{
    size_t slice = ir->aeAadLen / MLT_UPDATE_COUNT;
    size_t used = 0;
    size_t left = ir->aeAadLen;
    size_t curAadLen = slice;
    size_t i;
    for (i = 0; i < MLT_UPDATE_COUNT; i++) {
        curAadLen = (i == (MLT_UPDATE_COUNT - 1) ? left : slice);
        TEE_AEUpdateAAD(ir->bckOperaHandle, ir->pAad + used, curAadLen);
        used += curAadLen;
        left = ir->aeAadLen - used;
    }
    tlogi("[%s]:AEUpdateAadMtlBck success\n", __func__);
    return 0;
}

int AEUpdateBck(IntermediateReprestation *ir)
{
    if (ir->plainData.dataMode == DATA_MODE_WHOLE) {
        tlogi("[%s]:dataMode is whole, not slice, just return.\n", __func__);
        return 0;
    }
    void *pSrcData = ir->cipherData.data + ir->cipherData.dataUsed;
    size_t dataLeft = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    size_t srcLen = (dataLeft >= ir->cipherData.sliceSize) ? ir->cipherData.sliceSize :  0;
    void *pDestData = ir->decryptedData.data + ir->decryptedData.dataUsed;
    size_t destLen = ir->decryptedData.dataSize - ir->decryptedData.dataUsed;
    int ret = TEE_AEUpdate(ir->bckOperaHandle, pSrcData, srcLen, pDestData, &destLen);
    if (ret != 0) {
        tloge("[%s]:TEE_AEUpdate failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }
    ir->cipherData.dataUsed += srcLen;
    ir->decryptedData.dataUsed += destLen;
    tlogi("[%s]:AEUpdateBck success.\n", __func__);
    return 0;
}

int AEUpdate0Bck(IntermediateReprestation *ir)
{
    void *pDestData = ir->decryptedData.data + ir->decryptedData.dataUsed;
    size_t destLen = ir->decryptedData.dataSize - ir->decryptedData.dataUsed;
    int ret = TEE_AEUpdate(ir->bckOperaHandle, NULL, 0, pDestData, &destLen);
    if (ret != 0) {
        tloge("[%s]:TEE_AEUpdate failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }

    tlogi("[%s]:AEUpdate0Bck success.\n", __func__);
    return 0;
}

int AEDoFinalBck(IntermediateReprestation *ir)
{
    int ret;
    size_t dataLeft = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    while (ir->cipherData.dataMode != DATA_MODE_WHOLE &&
        dataLeft > ir->cipherData.sliceSize) {
            ret = AEUpdateBck(ir);
            if (ret != 0) {
                tloge("[%s]:AEUpdateBck failed\n", __func__);
                return -1;
            }
            dataLeft = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    }
    void *srcData = ir->cipherData.data + ir->cipherData.dataUsed;
    size_t srcLen = dataLeft;
    void *destData = ir->decryptedData.data + ir->decryptedData.dataUsed;
    size_t destLen = ir->decryptedData.dataSize - ir->decryptedData.dataUsed;
    void *tag = ir->aeTag;
    size_t tagLen = ir->aeTagOSize;
    ret = TEE_AEDecryptFinal(ir->bckOperaHandle, srcData, srcLen, destData, &destLen, tag, tagLen);
    if (ret != 0) {
        tloge("[%s]:TEE_AEDecryptFinal failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }
    ir->decryptedData.dataSize = ir->decryptedData.dataUsed + destLen;
    tlogi("[%s]:TEE_AEDecryptFinal success\n", __func__);

    if (TEE_MemCompare((void *)ir->plainData.data,
        (void *)ir->decryptedData.data,
        (size_t)ir->plainData.dataSize)) {
        tloge("[%s]:TEE_MemCompare failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:AEDoFinalBck success\n", __func__);
    return 0;
}

int AEDoFinalOmtBck(IntermediateReprestation *ir)
{
    int ret;
    size_t dataLeft = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    while (ir->cipherData.dataMode != DATA_MODE_WHOLE &&
        dataLeft > ir->cipherData.sliceSize) {
            ret = AEUpdateBck(ir);
            if (ret != 0) {
                tloge("[%s]:AEUpdateBck failed\n", __func__);
                return -1;
            }
            dataLeft = ir->cipherData.dataSize - ir->cipherData.dataUsed;
    }
    void *srcData = ir->cipherData.data + ir->cipherData.dataUsed;
    size_t srcLen = dataLeft;
    size_t destLen;
    destLen = 0;
    void *tag = ir->aeTag;
    size_t tagLen = ir->aeTagOSize;
    ret = TEE_AEDecryptFinal(ir->bckOperaHandle, srcData, srcLen, NULL, &destLen, tag, tagLen);
    if (ret != 0) {
        tloge("[%s]:TEE_AEDecryptFinal failed, ret = 0x%x\n", __func__, ret);
        return ret;
    }

    tlogi("[%s]:AEDoFinalOmtBck success\n", __func__);
    return 0;
}
static uint32_t g_mgfList[RSA_ENCYPT_MGF_COUNT] = {
    TEE_DH_HASH_SHA1_mode, TEE_DH_HASH_SHA1_mode,
    TEE_DH_HASH_SHA224_mode, TEE_DH_HASH_SHA256_mode,
    TEE_DH_HASH_SHA384_mode, TEE_DH_HASH_SHA512_mode,
};
int ASEncryFwd(IntermediateReprestation *ir)
{
    ir->plainData.dataUsed = 0;
    ir->cipherData.dataSize = ir->cipherData.dataMallocSize;
    ir->cipherData.dataUsed = 0;

    TEE_Attribute attr = {
        .attributeID = TEE_ATTR_RSA_MGF1_HASH,
        .content = {
            .value = {
                .a = g_mgfList[ir->rsaEnMgf1Hash % RSA_ENCYPT_MGF_COUNT],
                .b = 0,
            },
        },
    };
    TEE_Attribute *params = (ir->rsaEnMgf1Hash == RSA_ENCRYPT_MGF_DEF) ? NULL : &attr;
    uint32_t paramCount = (ir->rsaEnMgf1Hash == RSA_ENCRYPT_MGF_DEF) ? 0 : 1;
    
    memset_s(ir->plainData.data, ir->plainData.dataSize, 0, 1);
    int ret = TEE_AsymmetricEncrypt(ir->fwdOperaHandle, (const TEE_Attribute *)params, paramCount,
        ir->plainData.data, ir->plainData.dataSize, ir->cipherData.data, &(ir->cipherData.dataSize));
    if (ret != 0) {
        tloge("[%]:TEE_AsymmetricEncrypt failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:ASEncryFwd success\n", __func__);
    return 0;
}

int ASDecryBck(IntermediateReprestation *ir)
{
    ir->cipherData.dataUsed = 0;
    ir->decryptedData.dataSize = ir->decryptedData.dataMallocSize;
    ir->decryptedData.dataUsed = 0;

    TEE_Attribute attr = {
        .attributeID = TEE_ATTR_RSA_MGF1_HASH,
        .content = {
            .value = {
                .a = g_mgfList[ir->rsaEnMgf1Hash % RSA_ENCYPT_MGF_COUNT],
                .b = 0,
            },
        },
    };
    TEE_Attribute *params = (ir->rsaEnMgf1Hash == RSA_ENCRYPT_MGF_DEF) ? NULL : &attr;
    uint32_t paramCount = (ir->rsaEnMgf1Hash == RSA_ENCRYPT_MGF_DEF) ? 0 : 1;

    int ret = TEE_AsymmetricDecrypt(ir->bckOperaHandle, (const TEE_Attribute *)params, paramCount,
        (void *)ir->cipherData.data, ir->cipherData.dataSize,
        (void *)ir->decryptedData.data, &(ir->decryptedData.dataSize));
    if (ret != 0) {
        tloge("[%s]:TEE_AsymmetricDecrypt failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:TEE_AsymmetricDecrypt success\n", __func__);

    if (ir->plainData.dataSize != ir->decryptedData.dataSize) {
        tloge("[%s]:ir->plainData.dataSize %u != ir->decryptedData.dataSize %u\n",
            __func__, ir->plainData.dataSize, ir->decryptedData.dataSize);
        return -1;
    }
    tlogi("[%s]:plainSize == decryptSize\n", __func__);

    if (TEE_MemCompare((void *)ir->plainData.data,
        (void *)ir->decryptedData.data,
        (size_t)ir->plainData.dataSize)) {
        tloge("[%s]:TEE_MemCompare failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:ASDecryBck success\n", __func__);
    return 0;
}

int ASSignFwd(IntermediateReprestation *ir)
{
    ir->plainData.dataUsed = 0;
    ir->cipherData.dataSize = ir->cipherData.dataMallocSize;
    ir->cipherData.dataUsed = 0;

    TEE_Attribute attr = {
        .attributeID = TEE_ATTR_RSA_PSS_SALT_LENGTH,
        .content = {
            .value = {
                .a = ir->rsaSgPssLen,
                .b = 0,
            },
        },
    };
    TEE_Attribute *params = (ir->rsaSgPssLen == 0) ? NULL : &attr;
    uint32_t paramCount = (ir->rsaSgPssLen == 0) ? 0 : 1;
    int ret = TEE_AsymmetricSignDigest(ir->fwdOperaHandle, (const TEE_Attribute *)params, paramCount,
        (void *)ir->plainData.data, ir->plainData.dataSize,
        (void *)ir->cipherData.data, &(ir->cipherData.dataSize));
    if (ret != 0) {
        tloge("[%s]:TEE_AsymmetricSignDigest failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:ASSignFwd success\n", __func__);
    return 0;
}

int ASVerifyBck(IntermediateReprestation *ir)
{
    TEE_Attribute attr = {
        .attributeID = TEE_ATTR_RSA_PSS_SALT_LENGTH,
        .content = {
            .value = {
                .a = ir->rsaSgPssLen,
                .b = 0,
            },
        },
    };
    TEE_Attribute *params = (ir->rsaSgPssLen == 0) ? NULL : &attr;
    uint32_t paramCount = (ir->rsaSgPssLen == 0) ? 0 : 1;
    int ret = TEE_AsymmetricVerifyDigest(ir->bckOperaHandle, (const TEE_Attribute *)params, paramCount,
        (void *)ir->plainData.data, ir->plainData.dataSize,
        (void *)ir->cipherData.data, ir->cipherData.dataSize);
    if (ret != 0) {
        tloge("[%s]:TEE_AsymmetricVerifyDigest failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:ASVerifyBck success\n", __func__);
    return 0;
}

int DRDeriveFwd(IntermediateReprestation *ir)
{
    ir->cipherData.dataSize = ir->cipherData.dataMallocSize;

    TEE_ObjectHandle derivedKey = NULL;
    int ret = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, 2048, &derivedKey);
    if (ret != 0) {
        tloge("[%s]:TEE_AllocateTransientObject TEE_TYPE_GENERIC_SECRET failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:TEE_AllocateTransientObject TEE_TYPE_GENERIC_SECRET success\n", __func__);

    TEE_Attribute *pParams = (ir->tki->keyObjList[1])->Attribute;
    uint32_t paramCount = (ir->tki->keyObjList[1])->attributesLen;
    TEE_DeriveKey(ir->fwdOperaHandle, pParams, paramCount, derivedKey);

    uint8_t *pTmp = TEE_Malloc(derivedKey->Attribute[0].content.ref.length, 0);
    if (pTmp == NULL) {
        tloge("[%s]:malloc failed\n", __func__);
        TEE_FreeTransientObject(derivedKey);
        return -1;
    }
    if (!TEE_MemCompare(pTmp, derivedKey->Attribute[0].content.ref.buffer,
        derivedKey->Attribute[0].content.ref.length)) {
        tloge("[%s]:derived key is invalid\n", __func__);
        TEE_Free(pTmp);
        TEE_FreeTransientObject(derivedKey);
        return -1;
    }
    TEE_Free(pTmp);

    if (ir->cipherData.dataSize < derivedKey->Attribute[0].content.ref.length) {
        tloge("[%s]:invalid cipherData size %u\n", __func__, ir->cipherData.dataSize);
        TEE_FreeTransientObject(derivedKey);
        return -1;
    }

    TEE_MemMove(ir->cipherData.data,
                derivedKey->Attribute[0].content.ref.buffer,
                derivedKey->Attribute[0].content.ref.length);
    ir->cipherData.dataSize = derivedKey->Attribute[0].content.ref.length;
    TEE_FreeTransientObject(derivedKey);

    tlogi("[%s]:DRDeriveFwd success\n", __func__);
    return 0;
}

int DRDeriveBck(IntermediateReprestation *ir)
{
    TEE_ObjectHandle derivedKey = NULL;
    int ret = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, 2048, &derivedKey);
    if (ret != 0) {
        tloge("[%s]:TEE_AllocateTransientObject TEE_TYPE_GENERIC_SECRET failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:TEE_AllocateTransientObject TEE_TYPE_GENERIC_SECRET success\n", __func__);

    TEE_Attribute *pParams = (ir->tki->keyObjList[0])->Attribute;
    uint32_t paramCount = (ir->tki->keyObjList[0])->attributesLen;
    TEE_DeriveKey(ir->bckOperaHandle, pParams, paramCount, derivedKey);

    if (ir->cipherData.dataSize != derivedKey->Attribute[0].content.ref.length) {
        tloge("[%s]:derive key length not same\n", __func__);
        return -1;
    }
    if (TEE_MemCompare(ir->cipherData.data, derivedKey->Attribute[0].content.ref.buffer,
        derivedKey->Attribute[0].content.ref.length)) {
        tloge("[%s]:fwd and bck derived key is not same\n", __func__);
        TEE_FreeTransientObject(derivedKey);
        return -1;
    }
    TEE_FreeTransientObject(derivedKey);

    tlogi("[%s]:DRDeriveBck success\n", __func__);
    return 0;
}
