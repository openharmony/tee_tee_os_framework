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
        tloge("[%s]:CreatePersistentObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:CreatePersistentObject success\n", __func__);
    return 0;
}

int DeletePersistentObject(IntermediateReprestation *ir)
{
    TEE_Result res = TEE_CloseAndDeletePersistentObject1(ir->object);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:DeletePersistentObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:DeletePersistentObject success\n", __func__);
    return 0;
}

int OpenPersistentObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    tv->openObjectLen = strnlen(tv->openObjectID, TEE_DATA_MAX_POSITION);
    TEE_Result res = TEE_OpenPersistentObject(tv->storageID, tv->openObjectID, tv->openObjectLen,
        tv->openFlags, &(ir->object));
    if (res != TEE_SUCCESS) {
        tloge("[%s]:OpenPersistentObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:OpenPersistentObject success\n", __func__);
    return 0;
}

int CloseObject(IntermediateReprestation *ir)
{
    TEE_CloseObject(ir->object);
    ir->object = TEE_HANDLE_NULL;
    tlogi("[%s]:CloseObject success\n", __func__);
    return 0;
}

int SeekObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_SeekObjectData(ir->object, tv->seekOffset, tv->whence);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:SeekObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:SeekObject success\n", __func__);
    return 0;
}

int WriteObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    tv->writeBufferLen = strnlen(tv->writeBuffer, TEE_DATA_MAX_POSITION);
    TEE_Result res = TEE_WriteObjectData(ir->object, tv->writeBuffer, tv->writeBufferLen);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:WriteObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:WriteObject success\n", __func__);
    return 0;
}

int ReadObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_ReadObjectData(ir->object, (void *)ir->readBuffer, tv->readBufferLen, &(ir->readCount));
    if (res != TEE_SUCCESS) {
        tloge("[%s]:WriteObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:ReadObject success\n", __func__);
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
        tloge("[%s]:TruncateObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:TruncateObject success\n", __func__);
    return 0;
}

int RenameObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    tv->newObjectLen = strnlen(tv->newObjectID, TEE_DATA_MAX_POSITION);
    TEE_Result res = TEE_RenamePersistentObject(ir->object, tv->newObjectID, tv->newObjectLen);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:RenameObject failed, 0x%x\n", __func__, res);
        return res;
    }

    tlogi("[%s]:RenameObject success\n", __func__);
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
        tloge("[%s]:GetObjectInfo failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:GetObjectInfo success\n", __func__);
    return 0;
}

int CheckObjectSize(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    if (ir->objectInfo.dataSize != tv->resetSize) {
        tloge("[%s]:CheckObjectSize data size error\n", __func__);
        return -1;
    }
    tlogi("[%s]:CheckObjectSize success\n", __func__);
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
        *((uint8_t *)tv->createObjectID) = '0' + i;
        res = TEE_CreatePersistentObject(tv->storageID, tv->createObjectID, tv->createObjectLen,
            tv->createFlags, tv->attributes, tv->initialData, tv->initialDataLen, &(ir->object));
        if (res != TEE_SUCCESS) {
            tloge("[%s]:CreateMultiObject failed, id %d, res 0x%x\n", __func__, i, res);
            return res;
        }
        TEE_CloseObject(ir->object);
    }
    tlogi("[%s]:CreateMultiObject success\n", __func__);
    return 0;
}

int AllocateEnumerator(IntermediateReprestation *ir)
{
    TEE_Result res = TEE_AllocatePersistentObjectEnumerator(&(ir->objectEnumerator));
    if (res != TEE_SUCCESS) {
        tloge("[%s]:AllocateEnumerator failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:AllocateEnumerator success\n", __func__);
    return 0;
}

int FreeEnumerator(IntermediateReprestation *ir)
{
    TEE_FreePersistentObjectEnumerator(ir->objectEnumerator);
    tlogi("[%s]:FreeEnumerator success\n", __func__);
    return 0;
}

int ResetEnumerator(IntermediateReprestation *ir)
{
    TEE_ResetPersistentObjectEnumerator(ir->objectEnumerator);
    tlogi("[%s]:ResetEnumerator success\n", __func__);
    return 0;
}

int StartEnumerator(IntermediateReprestation *ir)
{
    TEE_Result res = TEE_StartPersistentObjectEnumerator(ir->objectEnumerator, ir->tv->storageID);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:StartEnumerator failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:StartEnumerator success\n", __func__);
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
            tloge("[%s]:GetNextObject failed, 0x%x\n", __func__, res);
            return res;
        }
        res = TEE_OpenPersistentObject(tv->storageID, ir->enumObjectID, ir->enumObjectIDLen,
            tv->openFlags, &(ir->object));
        if (res != TEE_SUCCESS) {
            tloge("[%s]:GetNextObject open object failed, 0x%x\n", __func__, res);
            return res;
        }
        object_num++;
        TEE_CloseAndDeletePersistentObject(ir->object);
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
            tloge("[%s]:AllocateTransientObject failed, Object %d, 0x%x\n", __func__, i, res);
            return res;
        }
    }
    tlogi("[%s]:AllocateTransientObject success\n", __func__);
    return 0;
}

int FreeTransientObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    for (uint32_t i = 0; i < tv->transientObjectNum; ++i) {
        TEE_FreeTransientObject(ir->transientObject[i]);
    }
    tlogi("[%s]:FreeTransientObject success\n", __func__);
    return 0;
}

int RestrictObjectUsage(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_RestrictObjectUsage1(ir->transientObject[0], tv->objectUsage[ir->restrictUsageCount]);
    ir->restrictUsageCount++;
    if (res != TEE_SUCCESS) {
        tloge("[%s]:RestrictObjectUsage failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:RestrictObjectUsage success\n", __func__);
    return 0;
}

int ResetObject(IntermediateReprestation *ir)
{
    TEE_ResetTransientObject(ir->transientObject[0]);
    tlogi("[%s]:RestrictObjectUsage success\n", __func__);
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
    tlogi("[%s]:InitRefAttr success\n", __func__);
    return 0;
}

int InitValueAttr(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_InitValueAttribute(&(ir->attr[ir->initAttrNum]), tv->attributeID[ir->initAttrNum],
        tv->attrInitA[ir->initValueAddrCount], tv->attrInitB[ir->initValueAddrCount]);

    ir->initValueAddrCount++;
    ir->initAttrNum++;
    tlogi("[%s]:InitValueAttr success\n", __func__);
    return 0;
}

int PopulateTransientObject(IntermediateReprestation *ir)
{
    TestVector *tv = ir->tv;
    TEE_Result res = TEE_PopulateTransientObject(ir->transientObject[0], &(ir->attr[0]), tv->attrCount);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:PopulateTransientObject failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:PopulateTransientObject success\n", __func__);
    return 0;
}

int CopyObjectAttr(IntermediateReprestation *ir)
{
    TEE_Result res = TEE_CopyObjectAttributes1(ir->transientObject[1], ir->transientObject[0]);
    if (res != TEE_SUCCESS) {
        tloge("[%s]:CopyObjectAttr failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:CopyObjectAttr success\n", __func__);
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
        tloge("[%s]:GetObjectBufferAttr failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:GetObjectBufferAttr success\n", __func__);
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
        tloge("[%s]:GetObjectValueAttr failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:GetObjectValueAttr success\n", __func__);
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
        tloge("[%s]:GenerateKey failed, 0x%x\n", __func__, res);
        return res;
    }
    tlogi("[%s]:GenerateKey success\n", __func__);
    return 0;
}
