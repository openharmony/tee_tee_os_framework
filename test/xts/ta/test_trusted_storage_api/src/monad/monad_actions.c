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
#include "string.h"
#include "securec.h"
#include "tee_log.h"
#include "monad.h"

int IRSetUp(IntermediateReprestation *ir)
{
    int ret;

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
    int ret;

    ret = BalanceGroupElement(ir->mrpl, ir->mrplSize, IRTearDown);
    if (ret != 0) {
        tloge("[%s]:BalanceGroupElement failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:IRTearDown success\n", __func__);
    return 0;
}

/* Persistent Object Functions */
int CreatePersistentObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    tv->createObjectLen = strnlen(tv->createObjectID, TEE_DATA_MAX_POSITION);
    tv->initialDataLen = strnlen(tv->initialData, TEE_DATA_MAX_POSITION);
    TEE_Result res = TEE_CreatePersistentObject(tv->storageID, tv->createObjectID, tv->createObjectLen,
        tv->createFlags, tv->attributes, tv->initialData, tv->initialDataLen, &(ir->object));
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_CreatePersistentObject failed, 0x%x\n", __func__, res);
        return res;
    }

    int ret = DisbalanceGroupElement(ir->mrpl, ir->mrplSize, CreatePersistentObject);
    if (ret != 0) {
        tloge("[%s]:DisbalanceGroupElement failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:TEE_CreatePersistentObject success\n", __func__);
    return 0;
}

int DeletePersistentObject(IntermediateReprestation *ir)
{
    TEE_Result res = TEE_CloseAndDeletePersistentObject1(ir->object);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_CloseAndDeletePersistentObject1 failed, 0x%x\n", __func__, res);
        return res;
    }

    int ret = BalanceGroupElement(ir->mrpl, ir->mrplSize, DeletePersistentObject);
    if (ret != 0) {
        tloge("[%s]:BalanceGroupElement failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:TEE_CloseAndDeletePersistentObject1 success\n", __func__);
    return 0;
}

int OpenPersistentObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    tv->openObjectLen = strnlen(tv->openObjectID, TEE_DATA_MAX_POSITION);
    TEE_Result res = TEE_OpenPersistentObject(tv->storageID, tv->openObjectID, tv->openObjectLen,
        tv->openFlags, &(ir->object));
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_OpenPersistentObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_OpenPersistentObject success\n", __func__);
    return 0;
}

int CloseObject(IntermediateReprestation *ir)
{
    TEE_CloseObject(ir->object);
    ir->object = TEE_HANDLE_NULL;
    tlogi("[%s]:TEE_CloseObject success\n", __func__);
    return 0;
}

int SyncPersistentObject(IntermediateReprestation *ir)
{
    TEE_Result res = TEE_SyncPersistentObject(ir->object);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_SyncPersistentObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_SyncPersistentObject success\n", __func__);
    return 0;
}

int SeekObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_SeekObjectData(ir->object, tv->seekOffset, tv->whence);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_SeekObjectData failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_SeekObjectData success\n", __func__);
    return 0;
}

int WriteObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    tv->writeBufferLen = strnlen(tv->writeBuffer, TEE_DATA_MAX_POSITION);
    TEE_Result res = TEE_WriteObjectData(ir->object, tv->writeBuffer, tv->writeBufferLen);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_WriteObjectData failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_WriteObjectData success\n", __func__);
    return 0;
}

int ReadObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_ReadObjectData(ir->object, (void *)ir->readBuffer, tv->readBufferLen, &(ir->readCount));
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_ReadObjectData failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_ReadObjectData success\n", __func__);
    return 0;
}

int CheckReadBuffer(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    if (ir->readCount != tv->writeBufferLen) {
        tloge("[%s]:CheckReadBuffer compare dataLen fail\n", __func__);
        return -1;
    }

    int res = strncmp(tv->writeBuffer, ir->readBuffer, ir->readCount);
    if (res != 0) {
        tloge("[%s]:CheckReadBuffer compare data fail\n", __func__);
        return -1;
    }
    tlogi("[%s]:CheckReadBuffer success\n", __func__);
    return 0;
}

int TruncateObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_TruncateObjectData(ir->object, tv->resetSize);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_TruncateObjectData failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_TruncateObjectData success\n", __func__);
    return 0;
}

int RenameObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    tv->newObjectLen = strnlen(tv->newObjectID, TEE_DATA_MAX_POSITION);
    TEE_Result res = TEE_RenamePersistentObject(ir->object, tv->newObjectID, tv->newObjectLen);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_RenamePersistentObject failed, 0x%x\n", __func__, res);
        return res;
    }

    tlogi("[%s]:TEE_RenamePersistentObject success\n", __func__);
    return 0;
}

int GetObjectInfo(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_SUCCESS;
    if (tv->isTransientObject) {
        res = TEE_GetObjectInfo1(ir->transientObject[0], &(ir->objectInfo));
    } else {
        res = TEE_GetObjectInfo1(ir->object, &(ir->objectInfo));
    }
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_GetObjectInfo1 failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_GetObjectInfo1 success\n", __func__);
    return 0;
}

int InfoObjectData(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_SUCCESS;
    if (tv->isTransientObject) {
        res = TEE_InfoObjectData(ir->transientObject[0], &(ir->pos), &(ir->len));
    } else {
        res = TEE_InfoObjectData(ir->object, &(ir->pos), &(ir->len));
    }
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_InfoObjectData failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_InfoObjectData success, ir->pos=%d, ir->len=%d\n", __func__, ir->pos, ir->len);
    return 0;
}

int CheckObjectSize(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    if (ir->objectInfo.dataSize != tv->resetSize) {
        tloge("[%s]:CheckObjectSize data size error, get objectInfo.dataSize=%d\n", __func__, ir->objectInfo.dataSize);
        return -1;
    }
    tlogi("[%s]:CheckObjectSize success\n", __func__);
    return 0;
}

int CheckInfoObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    if (ir->len != tv->resetSize) {
        tloge("[%s]:CheckInfoObject data len error, get len = %d\n", __func__, ir->len);
        return -1;
    }
    if (ir->pos != 0) {
        tloge("[%s]:CheckInfoObject data pos error, get pos = %d\n", __func__, ir->pos);
        return -1;
    }
    tlogi("[%s]:CheckInfoObject success\n", __func__);
    return 0;
}

/* Persistent Object Enumeration Functions */
int CreateMultiObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_SUCCESS;
    tv->createObjectLen = strnlen(tv->createObjectID, TEE_DATA_MAX_POSITION);
    tv->initialDataLen = strnlen(tv->initialData, TEE_DATA_MAX_POSITION);
    for (uint32_t i = 0; i < tv->createNum; ++i) {
        *((uint8_t *)tv->createObjectID + tv->createObjectLen - 1) = '0' + i;  // only change last char
        res = TEE_CreatePersistentObject(tv->storageID, tv->createObjectID, tv->createObjectLen,
            tv->createFlags, tv->attributes, tv->initialData, tv->initialDataLen, &(ir->object));
        if (res != TEE_SUCCESS) {
            tloge("[%s]:TEE_CreatePersistentObject failed, id %d, res 0x%x\n", __func__, i, res);
            return res;
        }
        TEE_CloseObject(ir->object);
    }

    int ret = DisbalanceGroupElement(ir->mrpl, ir->mrplSize, CreateMultiObject);
    if (ret != 0) {
        tloge("[%s]:DisbalanceGroupElement failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:TEE_CreatePersistentObject success\n", __func__);
    return 0;
}

int DeleteMultiObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res;
    int error = 0;
    for (uint32_t i = 0; i < tv->createNum; ++i) {
        tv->openObjectLen = strnlen(tv->openObjectID, TEE_DATA_MAX_POSITION);
        *((uint8_t *)tv->openObjectID + tv->openObjectLen - 1) = '0' + i; 
        res = TEE_OpenPersistentObject(tv->storageID, tv->openObjectID, tv->openObjectLen,
            tv->openFlags, &(ir->object));
        if ((res != TEE_SUCCESS) && (res != TEE_ERROR_ITEM_NOT_FOUND)) {
            error++;
            tloge("[%s]:TEE_OpenPersistentObject failed, 0x%x\n", __func__, res);
            continue;
        }

        if (res == TEE_SUCCESS) {
            res = TEE_CloseAndDeletePersistentObject1(ir->object);
            if (res != TEE_SUCCESS) {
                error++;
                tloge("[%s]:TEE_CloseAndDeletePersistentObject1 failed, 0x%x\n", __func__, res);
                continue;
            }
        }
    }

    if (error) {
        tloge("[%s]:TEE_OpenPersistentObject or TEE_CloseAndDeletePersistentObject1 failed\n", __func__);
        return -1;
    } 

    tlogi("[%s]:TEE_OpenPersistentObject or TEE_CloseAndDeletePersistentObject1 success\n", __func__);   
    
    int ret = BalanceGroupElement(ir->mrpl, ir->mrplSize, DeleteMultiObject);
    if (ret != 0) {
        tloge("[%s]:BalanceGroupElement failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:TEE_CloseAndDeletePersistentObject1 all object success\n", __func__);
    return 0;
}

int AllocateEnumerator(IntermediateReprestation *ir)
{
    TEE_Result res = TEE_AllocatePersistentObjectEnumerator(&(ir->objectEnumerator));
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_AllocatePersistentObjectEnumerator failed, 0x%x\n", __func__, res);
        return res;
    }

    int ret = DisbalanceGroupElement(ir->mrpl, ir->mrplSize, AllocateEnumerator);
    if (ret != 0) {
        tloge("[%s]:DisbalanceGroupElement failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:TEE_AllocatePersistentObjectEnumerator success\n", __func__);
    return 0;
}

int FreeEnumerator(IntermediateReprestation *ir)
{
    TEE_FreePersistentObjectEnumerator(ir->objectEnumerator);

    int ret = BalanceGroupElement(ir->mrpl, ir->mrplSize, FreeEnumerator);
    if (ret != 0) {
        tloge("[%s]:BalanceGroupElement failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:TEE_FreePersistentObjectEnumerator success\n", __func__);
    return 0;
}

int ResetEnumerator(IntermediateReprestation *ir)
{
    TEE_ResetPersistentObjectEnumerator(ir->objectEnumerator);
    tlogi("[%s]:TEE_ResetPersistentObjectEnumerator success\n", __func__);
    return 0;
}

int StartEnumerator(IntermediateReprestation *ir)
{
    TEE_Result res = TEE_StartPersistentObjectEnumerator(ir->objectEnumerator, ir->tv->storageID);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_StartPersistentObjectEnumerator failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_StartPersistentObjectEnumerator success\n", __func__);
    return 0;
}

int EnumerateAllObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_SUCCESS;
    int object_num = 0;
    while (1) {
        ir->enumObjectIDLen = MAX_DATA_LEN;
        res = TEE_GetNextPersistentObject(ir->objectEnumerator, &(ir->objectInfo),
            ir->enumObjectID, &(ir->enumObjectIDLen));
        if (res == TEE_ERROR_ITEM_NOT_FOUND) {
            break;
        }
        if (res != TEE_SUCCESS) {
            tloge("[%s]:TEE_GetNextPersistentObject failed, 0x%x\n", __func__, res);
            return res;
        }
        res = TEE_OpenPersistentObject(tv->storageID, ir->enumObjectID, ir->enumObjectIDLen,
            tv->openFlags, &(ir->object));
        if (res != TEE_SUCCESS) {
            tloge("[%s]:TEE_GetNextPersistentObject open object failed, 0x%x\n", __func__, res);
            return res;
        }
        object_num++;
        res = TEE_CloseAndDeletePersistentObject1(ir->object);
        if (res != TEE_SUCCESS) {
            tloge("[%s]:TEE_CloseAndDeletePersistentObject1 object failed, 0x%x\n", __func__, res);
        }
    }

    tlogi("[%s]:EnumerateAllObject success, object num %d\n", __func__, object_num);
    return 0;
}

/* TransientObject Functions */
int AllocateTransientObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_SUCCESS;
    for (uint32_t i = 0; i < tv->transientObjectNum; ++i) {
        res = TEE_AllocateTransientObject(tv->objectType[i], tv->maxObjectSize[i], &(ir->transientObject[i]));
        if (res != TEE_SUCCESS) {
            tloge("[%s]:TEE_AllocateTransientObject failed, Object %d, 0x%x\n", __func__, i, res);
            return res;
        }
    }

    int ret = DisbalanceGroupElement(ir->mrpl, ir->mrplSize, AllocateTransientObject);
    if (ret != 0) {
        tloge("[%s]:DisbalanceGroupElement failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:TEE_AllocateTransientObject success\n", __func__);
    return 0;
}

int FreeTransientObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    for (uint32_t i = 0; i < tv->transientObjectNum; ++i) {
        TEE_FreeTransientObject(ir->transientObject[i]);
    }

    int ret = BalanceGroupElement(ir->mrpl, ir->mrplSize, FreeTransientObject);
    if (ret != 0) {
        tloge("[%s]:BalanceGroupElement failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:TEE_FreeTransientObject success\n", __func__);
    return 0;
}

int RestrictObjectUsage(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_RestrictObjectUsage1(ir->transientObject[0], tv->objectUsage[ir->restrictUsageCount]);
    ir->restrictUsageCount++;
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_RestrictObjectUsage1 failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_RestrictObjectUsage1 success\n", __func__);
    return 0;
}

int ResetObject(IntermediateReprestation *ir)
{
    TEE_ResetTransientObject(ir->transientObject[0]);
    tlogi("[%s]:TEE_ResetTransientObject success\n", __func__);
    return 0;
}

int CheckObjectUsage(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    if (ir->objectInfo.objectUsage != tv->objectUsage[ir->checkUsageCount]) {
        tloge("[%s]:CheckObjectUsage check failed, objectUsage 0x%x, RestrictUsage 0x%x\n",
            __func__, ir->objectInfo.objectUsage, tv->objectUsage[ir->checkUsageCount]);
        return -1;
    }
    tloge("[%s]:CheckObjectUsage check failed, objectUsage 0x%x, RestrictUsage 0x%x\n",
        __func__, ir->objectInfo.objectUsage, tv->objectUsage[ir->checkUsageCount]);
    ir->checkUsageCount++;
    tlogi("[%s]:RestrictObjectUsage success\n", __func__);
    return 0;
}

/* TEE_Attribute Functions */
int InitRefAttr(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;

    tv->attrInitLength[ir->initRefAddrCount] = strnlen(tv->attrInitBuffer[ir->initRefAddrCount], TEE_DATA_MAX_POSITION);
    TEE_InitRefAttribute(&(ir->attr[ir->initAttrNum]), tv->attributeID[ir->initAttrNum],
        tv->attrInitBuffer[ir->initRefAddrCount], tv->attrInitLength[ir->initRefAddrCount]);

    ir->initRefAddrCount++;
    ir->initAttrNum++;
    tlogi("[%s]:TEE_InitRefAttribute success\n", __func__);
    return 0;
}

int InitValueAttr(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_InitValueAttribute(&(ir->attr[ir->initAttrNum]), tv->attributeID[ir->initAttrNum],
        tv->attrInitA[ir->initValueAddrCount], tv->attrInitB[ir->initValueAddrCount]);

    ir->initValueAddrCount++;
    ir->initAttrNum++;
    tlogi("[%s]:TEE_InitValueAttribute success\n", __func__);
    return 0;
}

int PopulateTransientObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_PopulateTransientObject(ir->transientObject[0], &(ir->attr[0]), tv->attrCount);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_PopulateTransientObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_PopulateTransientObject success\n", __func__);
    return 0;
}

int CopyObjectAttr(IntermediateReprestation *ir)
{
    TEE_Result res = TEE_CopyObjectAttributes1(ir->transientObject[1], ir->transientObject[0]);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_CopyObjectAttributes1 failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_CopyObjectAttributes1 success\n", __func__);
    return 0;
}

int GetObjectBufferAttr(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    ir->attrGetBufferLen[ir->getRefCount] = MAX_DATA_LEN;
    TEE_Result res = TEE_GetObjectBufferAttribute(ir->transientObject[1], tv->getAttributeID[ir->getAttrNum],
        &(ir->attrGetBuffer[ir->getRefCount]), &(ir->attrGetBufferLen[ir->getRefCount]));
    ir->getRefCount++;
    ir->getAttrNum++;
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_GetObjectBufferAttribute failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_GetObjectBufferAttribute success\n", __func__);
    return 0;
}

int GetObjectValueAttr(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_GetObjectValueAttribute(ir->transientObject[1], tv->getAttributeID[ir->getAttrNum],
        &(ir->attrGetA[ir->getValueCount]), &(ir->attrGetB[ir->getValueCount]));
    ir->getValueCount++;
    ir->getAttrNum++;
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_GetObjectValueAttribute failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_GetObjectValueAttribute success\n", __func__);
    return 0;
}

int CheckAttr(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    if (ir->attrGetBufferLen[0] != tv->attrInitLength[0] || ir->attrGetBufferLen[1] != tv->attrInitLength[1]) {
        tlogi("[%s]:CheckAttr attr_length failed\n", __func__);
        return -1;
    }
    if (strncmp(tv->attrInitBuffer[0], (void *)ir->attrGetBuffer[0], ir->attrGetBufferLen[0]) != 0 ||
        strncmp(tv->attrInitBuffer[1], (void *)ir->attrGetBuffer[1], ir->attrGetBufferLen[1]) != 0) {
        tlogi("[%s]:CheckAttr attr_buffer failed\n", __func__);
        return -1;
    }
    if (ir->attrGetBufferLen[0] != tv->attrInitLength[0] || ir->attrGetBufferLen[1] != tv->attrInitLength[1]) {
        tlogi("[%s]:CheckAttr attr_length failed\n", __func__);
        return -1;
    }

    tlogi("[%s]:CheckAttr success\n", __func__);
    return 0;
}

int GenerateKey(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_GenerateKey(ir->transientObject[0], tv->generateKeySize, ir->attr, tv->attrCount);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:TEE_GenerateKey failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TEE_GenerateKey success\n", __func__);
    return 0;
}
