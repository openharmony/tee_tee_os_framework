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
#ifndef TEST_TRUSTED_STORAGE_DEFINES_H
#define TEST_TRUSTED_STORAGE_DEFINES_H
#include "stddef.h"
#include "tee_trusted_storage_api.h"
#include "tee_object_api.h"
#include "tee_log.h"

struct _IntermediateReprestation;
typedef int (*ActionEntryType)(struct _IntermediateReprestation *ir);

#define MAX_STRING_NAME_LEN 100
#define MAX_ACTIONS_SIZE    100

#define MAX_DATA_LEN        1024
#define MAX_ACTION_LOOP_SIZE 10

// test vector
typedef struct {
    // start of declaration of user defined test data factors
    uint32_t storageID;

    void *createObjectID;
    size_t createObjectLen;
    uint32_t createFlags;
    uint32_t createNum;
    void* initialData;
    size_t initialDataLen;
    TEE_ObjectHandle attributes;

    void *openObjectID;
    size_t openObjectLen;
    uint32_t openFlags;

    int32_t seekOffset;
    TEE_Whence whence;
    void* writeBuffer;
    size_t writeBufferLen;
    size_t readBufferLen;

    void *newObjectID;
    size_t newObjectLen;
    size_t resetSize;

    uint32_t objectUsage[MAX_ACTION_LOOP_SIZE];
    uint32_t objectType[MAX_ACTION_LOOP_SIZE];
    uint32_t maxObjectSize[MAX_ACTION_LOOP_SIZE];
    uint32_t transientObjectNum;
    bool isTransientObject;

    uint32_t attributeID[MAX_ACTION_LOOP_SIZE];
    void *attrInitBuffer[MAX_ACTION_LOOP_SIZE];
    size_t attrInitLength[MAX_ACTION_LOOP_SIZE];
    uint32_t attrInitA[MAX_ACTION_LOOP_SIZE];
    uint32_t attrInitB[MAX_ACTION_LOOP_SIZE];
    uint32_t getAttributeID[MAX_ACTION_LOOP_SIZE];

    uint32_t generateKeySize;
    uint32_t attrCount;

    // end of declaration of user defined test data factors
    // start of declaration of factors of the test framework
    ActionEntryType actions[MAX_ACTIONS_SIZE];
    uint32_t expRet;
} TestVector;

// expect result
enum {
    ER_OK = 0,
    ER_JF = 1,
};

// inverse actions map info manage
enum {
    GROUP_BALANCED = 0,
    GROUP_NOT_BALANCED = 1,
};
typedef struct {
    char *elementName;
    ActionEntryType element;
    char *inverseElementName;
    ActionEntryType inverseElement;
    uint32_t isBalanced;
} MonadReversibilityProperty;

// intermediate represtation of test context
#define MONAD_REVERSE_PROP_LIST_SIZE 100
typedef struct _IntermediateReprestation {
    // start of declaration of user defined test data factors
    TEE_ObjectHandle object;
    TEE_ObjectInfo objectInfo;

    char readBuffer[MAX_DATA_LEN];
    uint32_t readCount;

    TEE_ObjectEnumHandle objectEnumerator;
    char enumObjectID[MAX_DATA_LEN];
    size_t enumObjectIDLen;

    TEE_ObjectHandle transientObject[MAX_ACTION_LOOP_SIZE];
    TEE_Attribute attr[MAX_ACTION_LOOP_SIZE];
    uint32_t initAttrNum;

    void *attrGetBuffer[MAX_ACTION_LOOP_SIZE][MAX_DATA_LEN];
    size_t attrGetBufferLen[MAX_ACTION_LOOP_SIZE];
    uint32_t attrGetA[MAX_ACTION_LOOP_SIZE];
    uint32_t attrGetB[MAX_ACTION_LOOP_SIZE];

    /* function invoke count */
    uint32_t getAttrNum;
    uint32_t getRefCount;
    uint32_t getValueCount;
    uint32_t restrictUsageCount;
    uint32_t checkUsageCount;
    uint32_t initRefAddrCount;
    uint32_t initValueAddrCount;
    uint32_t pos;
    uint32_t len;
    // end of declaration of user defined test data factors

    // start of declaration factors of the test framework
    TestVector *tv;
    MonadReversibilityProperty mrpl[MONAD_REVERSE_PROP_LIST_SIZE];
    uint32_t mrplSize;
} IntermediateReprestation;
#endif // end TEST_DEFINES_H